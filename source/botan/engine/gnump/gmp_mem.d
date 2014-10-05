/*
* GNU MP Memory Handlers
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.gnump_engine;
import cstring;
import atomic;
import gmp.h;
namespace {

/*
* For keeping track of existing GMP_Engines and only
* resetting the memory when none are in use.
*/
std::atomic<size_t> gmp_alloc_refcnt(0);

/*
* Allocation Function for GNU MP
*/
void* gmp_malloc(size_t n)
{
	// Maintain alignment, mlock goes for sizeof(T) alignment
	if (n % 8 == 0)
		return secure_allocator<ulong>().allocate(n / 8);
	else if (n % 4 == 0)
		return secure_allocator<uint>().allocate(n / 4);
	else if (n % 2 == 0)
		return secure_allocator<ushort>().allocate(n / 2);

	return secure_allocator<ubyte>().allocate(n);
}

/*
* Deallocation Function for GNU MP
*/
void gmp_free(void* ptr, size_t n)
{
	secure_allocator<ubyte>().deallocate(cast(ubyte*)(ptr), n);
}

/*
* Reallocation Function for GNU MP
*/
void* gmp_realloc(void* ptr, size_t old_n, size_t new_n)
{
	void* new_buf = gmp_malloc(new_n);
	std::memcpy(new_buf, ptr, std.algorithm.min(old_n, new_n));
	gmp_free(ptr, old_n);
	return new_buf;
}

}

/*
* GMP_Engine Constructor
*/
GMP_Engine::GMP_Engine()
{
	/*
	if (gmp_alloc_refcnt == 0)
		mp_set_memory_functions(gmp_malloc, gmp_realloc, gmp_free);

	gmp_alloc_refcnt++;
	*/
}

GMP_Engine::~this()
{
	/*
	--gmp_alloc_refcnt;

	if (gmp_alloc_refcnt == 0)
		mp_set_memory_functions(NULL, NULL, NULL);
	*/
}

}
