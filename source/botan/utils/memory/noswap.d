/*
* Mlock Allocator
* (C) 2012,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/
module botan.utils.memory.noswap;

import botan.utils.types;
import botan.utils.types;
import core.sync.mutex;

import botan.utils.mem_ops;
import std.algorithm;
// import string;

import core.sys.posix.sys.mman;
import core.sys.posix.sys.resource;

final class NoSwapAllocator
{
public:
	synchronized void[] alloc(size_t n)
	{
		if (!m_pool)
			return null;

		__gshared immutable size_t alignment = 8;
		
		if (n > m_poolsize || n > BOTAN_MLOCK_ALLOCATOR_MAX_ALLOCATION)
			return null;
				
		auto best_fit = m_freelist.end();
		
		for (auto i = m_freelist.ptr; i != m_freelist.end(); ++i)
		{
			// If we have a perfect fit, use it immediately
			if (i.second == n && (i.first % alignment) == 0)
			{
				const size_t offset = i.first;
				m_freelist.erase(i);
				clear_mem(m_pool + offset, n);
				
				assert((cast(size_t)(m_pool) + offset) % alignment == 0, "Returning correctly aligned pointer");
				
				return (m_pool + offset)[0 .. n];
			}
			
			if ((i.second >= (n + padding_for_alignment(i.first, alignment)) &&
			     ((best_fit == m_freelist.end()) || (best_fit.second > i.second))))
			{
				best_fit = i;
			}
		}
		
		if (best_fit != m_freelist.end())
		{
			const size_t offset = best_fit.first;
			
			const size_t alignment_padding = padding_for_alignment(offset, alignment);
			
			best_fit.first += n + alignment_padding;
			best_fit.second -= n + alignment_padding;
			
			// Need to realign, split the block
			if (alignment_padding)
			{
				/*
				If we used the entire block except for small piece used for
				alignment at the beginning, so just update the entry already
				in place (as it is in the correct location), rather than
				deleting the empty range and inserting the new one in the
				same location.
				*/
				if (best_fit.second == 0)
				{
					best_fit.first = offset;
					best_fit.second = alignment_padding;
				}
				else
					m_freelist.insert(best_fit, Pair(offset, alignment_padding));
			}
			
			clear_mem(m_pool + offset + alignment_padding, n);
			
			assert((cast(size_t)(m_pool) + offset + alignment_padding) % alignment == 0,
			             "Returning correctly aligned pointer");
			
			return (m_pool + offset + alignment_padding)[0 .. n];
		}
		
		return null;
	}

	synchronized bool free(void[] p)
	{
		if (!m_pool)
			return false;
		
		size_t n = p.length;
		
		/*
		We return null in allocate if there was an overflow, so we
		should never ever see an overflow in a deallocation.
		*/
		assert(n / elem_size == num_elems, "No overflow in deallocation");
		
		if (!ptr_in_pool(m_pool, m_poolsize, p, n))
			return false;
		
		m_mutex.lock(); scope(exit) m_mutex.unlock();
		
		const size_t start = cast(ubyte*)(p) - m_pool;
		
		auto comp = (Pair!(size_t, size_t) x, Pair!(size_t, size_t) y){ return x.first < y.first; };
		
		auto i = std::lower_bound(m_freelist.ptr, m_freelist.end(),
		                          Pair(start, 0), comp);
		
		// try to merge with later block
		if (i != m_freelist.end() && start + n == i.first)
		{
			i.first = start;
			i.second += n;
			n = 0;
		}
		
		// try to merge with previous block
		if (i != m_freelist.ptr)
		{
			auto prev = std::prev(i);
			
			if (prev.first + prev.second == start)
			{
				if (n)
				{
					prev.second += n;
					n = 0;
				}
				else
				{
					// merge adjoining
					prev.second += i.second;
					m_freelist.erase(i);
				}
			}
		}
		
		if (n != 0) // no merge possible?
			m_freelist.insert(i, Pair(start, n));
		
		return true;
	}
		
private:
	this()
	{
		m_poolsize = mlock_limit();
		m_pool = null;
		
		if (m_poolsize)
		{
			m_pool = cast(ubyte*)(mmap(null, m_poolsize,
			                           PROT_READ | PROT_WRITE,
			                           MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE,
			                           -1, 0));
			
			if (m_pool == cast(ubyte*)(MAP_FAILED))
			{
				m_pool = null;
				throw new Exception("Failed to mmap locking_allocator pool");
			}
			
			clear_mem(m_pool, m_poolsize);
			
			if (mlock(m_pool, m_poolsize) != 0)
			{
				munmap(m_pool, m_poolsize);
				m_pool = null;
				throw new Exception("Could not mlock " ~ to!string(m_poolsize) ~ " bytes");
			}
			
			madvise(m_pool, m_poolsize, MADV_DONTDUMP);
			
			m_freelist.push_back(Pair(0, m_poolsize));
		}
	}

	~this()
	{
		if (m_pool)
		{
			clear_mem(m_pool, m_poolsize);
			munlock(m_pool, m_poolsize);
			munmap(m_pool, m_poolsize);
			m_pool = null;
		}
	}
		
	const size_t m_poolsize;
	Vector!( Pair!(size_t, size_t) ) m_freelist;
	ubyte* m_pool;
}

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

bool ptr_in_pool(const void* pool_ptr, size_t poolsize, const void* buf_ptr, size_t bufsize)
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