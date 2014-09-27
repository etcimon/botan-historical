/*
* Mlock Allocator
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
import vector;
import mutex;
class mlock_allocator
{
	public:
		static mlock_allocator& instance();

		void* allocate(size_t num_elems, size_t elem_size);

		bool deallocate(void* p, size_t num_elems, size_t elem_size);

		mlock_allocator(in mlock_allocator);

		mlock_allocator& operator=(in mlock_allocator);

	private:
		mlock_allocator();

		~mlock_allocator();

		const size_t m_poolsize;

		std::mutex m_mutex;
		Vector!( Pair!(size_t, size_t) ) m_freelist;
		byte* m_pool;
};