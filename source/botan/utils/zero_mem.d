/*
* Zero Memory
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.mem_ops;
void zero_mem(void* ptr, size_t n)
{
	volatile byte* p = cast(volatile byte*)(ptr);

	for (size_t i = 0; i != n; ++i)
		p[i] = 0;
}

}
