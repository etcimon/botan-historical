/*
* Prefetching Operations
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.utils.cpuid;
void prefetch_readonly(T)(const T* addr, size_t length)
{
#if defined(__GNUG__)
    const size_t Ts_per_cache_line = CPUID.cache_line_size() / T.sizeof;

    for (size_t i = 0; i <= length; i += Ts_per_cache_line)
        __builtin_prefetch(addr + i, 0);
#endif
}

void prefetch_readwrite(T)(const T* addr, size_t length)
{
#if defined(__GNUG__)
    const size_t Ts_per_cache_line = CPUID.cache_line_size() / T.sizeof;

    for (size_t i = 0; i <= length; i += Ts_per_cache_line)
        __builtin_prefetch(addr + i, 1);
#endif
}