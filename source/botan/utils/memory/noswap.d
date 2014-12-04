/*
* Mlock Allocator
* (C) 2012,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/
module botan.utils.memory.noswap;

import botan.utils.types;
import botan.utils.mem_ops;
import botan.utils.containers.rbtree;
import std.algorithm;

version(Posix) {
    import core.sys.posix.sys.mman;
    import core.sys.posix.sys.resource;
}
version(Windows) {
private nothrow @nogc pure:
    import core.sys.windows.windows;

    extern(Windows) {
        BOOL VirtualLock(LPVOID lpAddress, SIZE_T dwSize);
        BOOL VirtualUnlock(LPVOID lpAddress, SIZE_T dwSize);
        LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
        BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
        BOOL SetProcessWorkingSetSize(HANDLE hProcess, SIZE_T dwMinimumWorkingSetSize, SIZE_T dwMaximumWorkingSetSize);
    }
    int mlock(void* ptr, size_t sz) {
        return cast(int) VirtualLock(cast(LPVOID) ptr, cast(SIZE_T) sz);
    }

    int munlock(void* ptr, size_t sz) {

        return cast(int) VirtualUnlock(cast(LPVOID) ptr, cast(SIZE_T) sz);
    }

    private void* mmap(void* ptr, size_t length, int prot, int flags, int fd, size_t offset) {
        enum MEM_RESERVE     = 0x00002000;
        enum MEM_COMMIT     = 0x00001000;
        enum PAGE_READWRITE = 0x04;
        return cast(void*) VirtualAlloc(cast(LPVOID) null, cast(SIZE_T) dwSize, cast(DWORD) (MEM_RESERVE | MEM_COMMIT), cast(DWORD) PAGE_READWRITE);
    }

    void munmap(void* ptr, size_t sz)
    {
        enum MEM_RELEASE = 0x8000;
        VirtualFree(cast(LPVOID) ptr, cast(SIZE_T) sz, cast(DWORD) MEM_RELEASE);
    }

}
final class NoSwapAllocator
{
    __gshared immutable size_t alignment = 8;

public:
    synchronized void[] alloc(size_t n)
    {
        if (!m_pool)
            return null;


        if (n > m_poolsize || n > BOTAN_MLOCK_ALLOCATOR_MAX_ALLOCATION)
            return null;
                
        void[]* best_fit_ref;
        void[] best_fit;
        size_t i;
        foreach (ref slot; m_freelist[])
        {
            // If we have a perfect fit, use it immediately
            if (slot.length == n && (slot.ptr % alignment) == 0)
            {
                m_freelist.removeKey(slot);
                clearMem(slot.ptr, slot.length);
                
                assert((slot.ptr - m_pool) % alignment == 0, "Returning correctly aligned pointer");
                
                return slot;
            }
            
            // import string;
            
            if (slot.length >= (n + padding_for_alignment(slot.ptr, alignment) ) &&
                ( !best_fit_ref || (best_fit.length > slot.length) ) )
            {
                best_fit_ref = &slot;
                best_fit = slot;
            }
            i++;
        }

        if (best_fit_ref)
        {
            const size_t alignment_padding = padding_for_alignment(best_fit.ptr, alignment);

            // absorb misalignment
            void[] remainder = (best_fit.ptr + n + alignment_padding)[0 .. best_fit.length - (n + alignment_padding)];
            if (remainder.length > 0) {
                *best_fit_ref = remainder;
            } else {
                m_freelist.removeKey(best_fit);
            }

            clearMem(best_fit.ptr + alignment_padding, n);
            
            assert((cast(size_t)(m_pool) + offset + alignment_padding) % alignment == 0, "Returning correctly aligned pointer");
            
            return (best_fit.ptr + alignment_padding)[0 .. n];
        }
        
        return null;
    }

    synchronized bool free(void[] mem)
    {
        import std.range : front, empty;

        if (!m_pool)
            return false;

        if (!ptr_in_pool(m_pool, m_poolsize, mem.ptr, mem.length))
            return false;
        
        m_mutex.lock(); scope(exit) m_mutex.unlock();

        bool is_merged;

        auto upper_range = m_freelist.upperBound(mem);
        if (!upper_range.empty && upper_range.front().ptr - alignment <= mem.ptr + mem.length)
        {
            // we can merge with the next block
            void[]* upper_elem = &upper_range.front();
            size_t alignment_padding = (*upper_elem).ptr - (mem.ptr + mem.length);
            void[] combined = mem.ptr[0 .. mem.ptr + mem.length + alignment_padding + upper_elem.length];

            *upper_elem = combined;
            is_merged = true;
        }
        else {
            auto lower_range = m_freelist.lowerBound(mem);
            if (!lower_range.empty && lower_range.back().ptr - alignment <= mem.ptr + mem.length)
            {
                // we can merge with the next block
                void[]* lower_elem = &lower_range.front();
                size_t alignment_padding = mem.ptr - ( (*lower_elem).ptr + lower_elem.length );
                void[] combined = (*lower_elem).ptr[0 .. lower_elem.ptr + lower_elem.length + alignment_padding + mem.length];
                
                *lower_elem = combined;
                is_merged = true;
            }
        }
        if (!is_merged) // no merge possible?
            m_freelist.insert(mem);
        
        return true;
    }
        
private:
    this()
    {

        m_poolsize = mlock_limit();
        
        if (m_poolsize)
        {
            m_pool_ptr = cast(ubyte*)(mmap(null, m_poolsize,
                                       PROT_READ | PROT_WRITE,
                                       MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE,
                                       -1, 0));
            
            if (m_pool_ptr == cast(ubyte*)(MAP_FAILED))
            {
                m_pool_ptr = null;
                throw new Exception("Failed to mmap locking_allocator pool");
            }
            
            clearMem(m_pool_ptr, m_poolsize);
            
            if (mlock(m_pool_ptr, m_poolsize) != 0)
            {
                munmap(m_pool_ptr, m_poolsize);
                m_pool_ptr = null;
                throw new Exception("Could not mlock " ~ to!string(m_poolsize) ~ " bytes");
            }
            
            version(Posix) madvise(m_pool_ptr, m_poolsize, MADV_DONTDUMP);

            m_pool = m_pool_ptr[m_pool_ptr + (m_pool_ptr % alignment) .. m_pool_ptr + m_poolsize - (m_poolsize % alignment)];

            m_freelist.pushBack(m_pool);
        }
    }

    ~this()
    {
        if (m_pool)
        {
            clearMem(m_pool_ptr, m_poolsize);
            munlock(m_pool_ptr, m_poolsize);
            munmap(m_pool_ptr, m_poolsize);
            m_pool = null;
            m_pool_ptr = null;
        }
    }
        
    const size_t m_poolsize;
    RedBlackTree!(void[], "a.ptr < b.ptr") m_freelist;
    void[] m_pool; // aligned
    void* m_pool_ptr;
}

private:

size_t mlock_limit()
{
    /*
    * Linux defaults to only 64 KiB of mlockable memory per process
    * (too small) but BSDs offer a small fraction of total RAM (more
    * than we need). Bound the total mlock size to 512 KiB which is
    * enough to run the entire test suite without spilling to non-mlock
    * memory (and thus presumably also enough for many useful
    * programs), but small enough that we should not cause problems
    * even if many processes are mlocking on the same machine.
    */
    __gshared immutable size_t MLOCK_UPPER_BOUND = 512*1024;

    version(Posix) {
        rlimit limits;
        getrlimit(RLIMIT_MEMLOCK, &limits);

        if (limits.rlim_cur < limits.rlim_max)
        {
            limits.rlim_cur = limits.rlim_max;
            setrlimit(RLIMIT_MEMLOCK, &limits);
            getrlimit(RLIMIT_MEMLOCK, &limits);
        }
        return std.algorithm.min(limits.rlim_cur, MLOCK_UPPER_BOUND);
    }
    version(Windows) {
        BOOL success = SetProcessWorkingSetSize(GetCurrentProcessId(), 512*1024, 315*4096);
        if (success == 0)
            return 0;
        return MLOCK_UPPER_BOUND;
    }
}

bool ptr_in_pool(in void* pool_ptr, size_t poolsize, in void* buf_ptr, size_t bufsize)
{
    if (buf_ptr < pool_ptr || buf_ptr >= pool_ptr + poolsize)
        return false;

    assert(buf_ptr + bufsize <= pool_ptr + poolsize, "Pointer does not partially overlap pool");

    return true;
}

size_t padding_for_alignment(size_t offset, size_t desired_alignment)
{
    size_t mod = offset % desired_alignment;
    if (mod == 0)
        return 0; // already right on
    return desired_alignment - mod;
}