/**
    Utility functions for memory management

    Note that this module currently is a big sand box for testing allocation related stuff.
    Nothing here, including the interfaces, is final but rather a lot of experimentation.

    Copyright: Â© 2012-2013 RejectedSoftware e.K.
    License: Subject to the terms of the MIT license, as written in the included LICENSE.txt file.
    Authors: SÃ¶nke Ludwig
*/
module botan.utils.memory.memory;

import core.exception : OutOfMemoryError;
import core.stdc.stdlib;
import core.memory;
import std.conv;
import std.exception : enforceEx;
import std.traits;
import std.algorithm;

alias VulnerableAllocator = LockAllocator!(DebugAllocator!(AutoFreeListAllocator!(MallocAllocator)));

package R getAllocator(R)() {
    static __gshared R alloc;
    if (!alloc)
        alloc = new R;
    return alloc;
}

auto allocObject(T, ALLOCATOR = Allocator, bool MANAGED = true, ARGS...)(ARGS args)
{
    auto mem = allocator.alloc(AllocSize!T);
    static if( MANAGED ){
        static if( hasIndirections!T )
            GC.addRange(mem.ptr, mem.length);
        return emplace!T(mem, args);
    }
    else static if( is(T == class) ) return cast(T)mem.ptr;
    else return cast(T*)mem.ptr;
}

T[] allocArray(T, ALLOCATOR = Allocator, bool MANAGED = true)(size_t n)
{
    auto allocator = getAllocator!ALLOCATOR();
    auto mem = allocator.alloc(T.sizeof * n);
    auto ret = cast(T[])mem;
    static if ( MANAGED )
    {
        static if( hasIndirections!T )
            GC.addRange(mem.ptr, mem.length);
        // TODO: use memset for class, pointers and scalars
        foreach (ref el; ret) { // calls constructors
            emplace!T(cast(void[])((&el)[0 .. 1]));
        }
    }
    return ret;
}

void freeArray(T, ALLOCATOR = Allocator, bool MANAGED = true)(ref T[] array)
{
    auto allocator = getAllocator!ALLOCATOR();
    static if (MANAGED && hasIndirections!T)
        GC.removeRange(array.ptr);
    static if (hasElaborateDestructor!T) // calls destructors
        foreach (ref e; array)
            .destroy(e);
    allocator.free(cast(void[])array);
    array = null;
}


interface Allocator {
    enum size_t alignment = 0x10;
    enum size_t alignmentMask = alignment-1;
    
    void[] alloc(size_t sz)
    out { assert((cast(size_t)__result.ptr & alignmentMask) == 0, "alloc() returned misaligned data."); }

    void free(void[] mem)
    in {
        assert(mem.ptr !is null, "free() called with null array.");
        assert((cast(size_t)mem.ptr & alignmentMask) == 0, "misaligned pointer passed to free().");
    }
}

/**
    Simple proxy allocator protecting its base allocator with a mutex.
*/
final class LockAllocator(Base) : Allocator {
    private {
        Base m_base;
    }
    this() { m_base = getAllocator!Base(); }
    void[] alloc(size_t sz) { synchronized(this) return m_base.alloc(sz); }
    void free(void[] mem)
    in {
        assert(mem.ptr !is null, "free() called with null array.");
        assert((cast(size_t)mem.ptr & alignmentMask) == 0, "misaligned pointer passed to free().");
    }
    body { synchronized(this) m_base.free(mem); }
}

final class DebugAllocator(Base) : Allocator {
    import botan.utils.hashmap : HashMap;
    private {
        Base m_baseAlloc;
        HashMap!(void*, size_t) m_blocks;
        size_t m_bytes;
        size_t m_maxBytes;
    }
    
    this()
    {
        m_baseAlloc = getAllocator!Base();
        m_blocks = HashMap!(void*, size_t)(get_allocator!VulnerableAllocator());
    }
    
    @property size_t allocatedBlockCount() const { return m_blocks.length; }
    @property size_t bytesAllocated() const { return m_bytes; }
    @property size_t maxBytesAllocated() const { return m_maxBytes; }
    
    void[] alloc(size_t sz)
    {
        auto ret = m_baseAlloc.alloc(sz);
        assert(ret.length == sz, "base.alloc() returned block with wrong size.");
        assert(m_blocks.get(ret.ptr, size_t.max) == size_t.max, "base.alloc() returned block that is already allocated.");
        m_blocks[ret.ptr] = sz;
        m_bytes += sz;
        if( m_bytes > m_maxBytes ){
            m_maxBytes = m_bytes;
            //logDebug("New allocation maximum: %d (%d blocks)", m_maxBytes, m_blocks.length);
        }
        return ret;
    }

    void free(void[] mem)
    {
        auto sz = m_blocks.get(mem.ptr, size_t.max);
        assert(sz != size_t.max, "free() called with non-allocated object.");
        assert(sz == mem.length, "free() called with block of wrong size.");
        m_baseAlloc.free(mem);
        m_bytes -= sz;
        m_blocks.remove(mem.ptr);
    }
}

final class MallocAllocator : Allocator {
    void[] alloc(size_t sz)
    {
        static err = new immutable OutOfMemoryError;
        auto ptr = .malloc(sz + Allocator.alignment);
        if (ptr is null) throw err;
        return adjustPointerAlignment(ptr)[0 .. sz];
    }
    
    void free(void[] mem)
    {
        .free(extractUnalignedPointer(mem.ptr));
    }
}

final class AutoFreeListAllocator(Base) : Allocator {
    import std.typetuple;
    
    private {
        enum minExponent = 5;
        enum freeListCount = 14;
        FreeListAlloc[freeListCount] m_freeLists;
        Base m_baseAlloc;
    }
    
    this()
    {
        m_baseAlloc = getAllocator!Base();
        foreach (i; iotaTuple!freeListCount)
            m_freeLists[i] = new FreeListAlloc(nthFreeListSize!(i), m_baseAlloc);
    }
    
    void[] alloc(size_t sz)
    {
        if (sz > nthFreeListSize!(freeListCount-1)) return m_baseAlloc.alloc(sz);
        foreach (i; iotaTuple!freeListCount)
            if (sz <= nthFreeListSize!(i))
                return m_freeLists[i].alloc().ptr[0 .. sz];
        //logTrace("AFL alloc %08X(%d)", ret.ptr, sz);
        assert(false);
    }
        
    void free(void[] data)
    {
        //logTrace("AFL free %08X(%s)", data.ptr, data.length);
        if (data.length > nthFreeListSize!(freeListCount-1)) {
            m_baseAlloc.free(data);
            return;
        }
        foreach(i; iotaTuple!freeListCount) {
            if (data.length <= nthFreeListSize!i) {
                m_freeLists[i].free(data.ptr[0 .. nthFreeListSize!i]);
                return;
            }
        }
        assert(false);
    }
    
    private static pure size_t nthFreeListSize(size_t i)() { return 1 << (i + minExponent); }
    private template iotaTuple(size_t i) {
        static if (i > 1) alias iotaTuple = TypeTuple!(iotaTuple!(i-1), i-1);
        else alias iotaTuple = TypeTuple!(0);
    }
}

final class FreeListAlloc(Base) : Allocator
{
    private static struct FreeListSlot { FreeListSlot* next; }
    private {
        immutable size_t m_elemSize;
        Base m_baseAlloc;
        FreeListSlot* m_firstFree = null;
        size_t m_nalloc = 0;
        size_t m_nfree = 0;
    }
    
    this(size_t elem_size, Allocator base_allocator)
    {
        assert(elem_size >= size_t.sizeof);
        m_elemSize = elem_size;
        m_baseAlloc = base_allocator;
        //logDebug("Create FreeListAlloc %d", m_elemSize);
    }
    
    @property size_t elementSize() const { return m_elemSize; }
    
    void[] alloc(size_t sz)
    {
        assert(sz == m_elemSize, "Invalid allocation size.");
        return alloc();
    }
    
    void[] alloc()
    {
        void[] mem;
        if( m_firstFree ){
            auto slot = m_firstFree;
            m_firstFree = slot.next;
            slot.next = null;
            mem = (cast(void*)slot)[0 .. m_elemSize];
            m_nfree--;
        } else {
            mem = m_baseAlloc.alloc(m_elemSize);
            //logInfo("Alloc %d bytes: alloc: %d, free: %d", SZ, s_nalloc, s_nfree);
        }
        m_nalloc++;
        //logInfo("Alloc %d bytes: alloc: %d, free: %d", SZ, s_nalloc, s_nfree);
        return mem;
    }

    void free(void[] mem)
    {
        assert(mem.length == m_elemSize, "Memory block passed to free has wrong size.");
        auto s = cast(FreeListSlot*)mem.ptr;
        s.next = m_firstFree;
        m_firstFree = s;
        m_nalloc--;
        m_nfree++;
    }
}

template FreeListObjectAlloc(T, bool USE_GC = true, bool INIT = true)
{
    enum ElemSize = AllocSize!T;
    
    static if( is(T == class) ){
        alias TR = T;
    } else {
        alias TR = T*;
    }
    
    TR alloc(ARGS...)(ARGS args)
    {
        //logInfo("alloc %s/%d", T.stringof, ElemSize);
        auto mem = get_allocator!VulnerableAllocator().alloc(ElemSize);
        static if( hasIndirections!T ) GC.addRange(mem.ptr, ElemSize);
        static if( INIT ) return emplace!T(mem, args);
        else return cast(TR)mem.ptr;
    }
    
    void free(TR obj)
    {
        static if( INIT ){
            auto objc = obj;
            .destroy(objc);//typeid(T).destroy(cast(void*)obj);
        }
        static if( hasIndirections!T ) GC.removeRange(cast(void*)obj);
        get_allocator!VulnerableAllocator().free((cast(void*)obj)[0 .. ElemSize]);
    }
}


template AllocSize(T)
{
    static if (is(T == class)) {
        // workaround for a strange bug where AllocSize!SSLStream == 0: TODO: dustmite!
        enum dummy = T.stringof ~ __traits(classInstanceSize, T).stringof;
        enum AllocSize = __traits(classInstanceSize, T);
    } else {
        enum AllocSize = T.sizeof;
    }
}

struct FreeListRef(T, bool INIT = true)
{
    enum ElemSize = AllocSize!T;
    
    static if( is(T == class) ){
        alias TR = T;
    } else {
        alias TR = T*;
    }
    
    private TR m_object;
    private size_t m_magic = 0x1EE75817; // workaround for compiler bug
    
    static FreeListRef opCall(ARGS...)(ARGS args)
    {
        //logInfo("refalloc %s/%d", T.stringof, ElemSize);
        FreeListRef ret;
        auto mem = get_allocator!VulnerableAllocator().alloc(ElemSize + int.sizeof);
        static if( hasIndirections!T ) GC.addRange(mem.ptr, ElemSize);
        static if( INIT ) ret.m_object = cast(TR)emplace!(Unqual!T)(mem, args);
        else ret.m_object = cast(TR)mem.ptr;
        ret.refCount = 1;
        return ret;
    }
    
    ~this()
    {
        //if( m_object ) logInfo("~this!%s(): %d", T.stringof, this.refCount);
        //if( m_object ) logInfo("ref %s destructor %d", T.stringof, refCount);
        //else logInfo("ref %s destructor %d", T.stringof, 0);
        clear();
        m_magic = 0;
        m_object = null;
    }
    
    this(this)
    {
        checkInvariants();
        if( m_object ){
            //if( m_object ) logInfo("this!%s(this): %d", T.stringof, this.refCount);
            this.refCount++;
        }
    }
    
    void opAssign(FreeListRef other)
    {
        clear();
        m_object = other.m_object;
        if( m_object ){
            //logInfo("opAssign!%s(): %d", T.stringof, this.refCount);
            refCount++;
        }
    }
    
    void clear()
    {
        checkInvariants();
        if( m_object ){
            if( --this.refCount == 0 ){
                static if( INIT ){
                    //logInfo("ref %s destroy", T.stringof);
                    //typeid(T).destroy(cast(void*)m_object);
                    auto objc = m_object;
                    .destroy(objc);
                    //logInfo("ref %s destroyed", T.stringof);
                }
                static if( hasIndirections!T ) GC.removeRange(cast(void*)m_object);
                get_allocator!VulnerableAllocator().free((cast(void*)m_object)[0 .. ElemSize+int.sizeof]);
            }
        }
        
        m_object = null;
        m_magic = 0x1EE75817;
    }
    
    @property const(TR) get() const { checkInvariants(); return m_object; }
    @property TR get() { checkInvariants(); return m_object; }
    alias get this;
    
    private @property ref int refCount()
    const {
        auto ptr = cast(ubyte*)cast(void*)m_object;
        ptr += ElemSize;
        return *cast(int*)ptr;
    }
    
    private void checkInvariants()
    const {
        assert(m_magic == 0x1EE75817);
        assert(!m_object || refCount > 0);
    }
}

private void* extractUnalignedPointer(void* base)
{
    ubyte misalign = *(cast(ubyte*)base-1);
    assert(misalign <= Allocator.alignment);
    return base - misalign;
}

private void* adjustPointerAlignment(void* base)
{
    ubyte misalign = Allocator.alignment - (cast(size_t)base & Allocator.alignmentMask);
    base += misalign;
    *(cast(ubyte*)base-1) = misalign;
    return base;
}

unittest {
    void testAlign(void* p, size_t adjustment) {
        void* pa = adjustPointerAlignment(p);
        assert((cast(size_t)pa & Allocator.alignmentMask) == 0, "Non-aligned pointer.");
        assert(*(cast(ubyte*)pa-1) == adjustment, "Invalid adjustment "~to!string(p)~": "~to!string(*(cast(ubyte*)pa-1)));
        void* pr = extractUnalignedPointer(pa);
        assert(pr == p, "Recovered base != original");
    }
    void* ptr = .malloc(0x40);
    ptr += Allocator.alignment - (cast(size_t)ptr & Allocator.alignmentMask);
    testAlign(ptr++, 0x10);
    testAlign(ptr++, 0x0F);
    testAlign(ptr++, 0x0E);
    testAlign(ptr++, 0x0D);
    testAlign(ptr++, 0x0C);
    testAlign(ptr++, 0x0B);
    testAlign(ptr++, 0x0A);
    testAlign(ptr++, 0x09);
    testAlign(ptr++, 0x08);
    testAlign(ptr++, 0x07);
    testAlign(ptr++, 0x06);
    testAlign(ptr++, 0x05);
    testAlign(ptr++, 0x04);
    testAlign(ptr++, 0x03);
    testAlign(ptr++, 0x02);
    testAlign(ptr++, 0x01);
    testAlign(ptr++, 0x10);
}

private size_t alignedSize(size_t sz)
{
    return ((sz + Allocator.alignment - 1) / Allocator.alignment) * Allocator.alignment;
}

unittest {
    foreach( i; 0 .. 20 ){
        auto ia = alignedSize(i);
        assert(ia >= i);
        assert((ia & Allocator.alignmentMask) == 0);
        assert(ia < i+Allocator.alignment);
    }
}

private void ensureValidMemory(void[] mem)
{
    auto bytes = cast(ubyte[])mem;
    swap(bytes[0], bytes[$-1]);
    swap(bytes[0], bytes[$-1]);
}