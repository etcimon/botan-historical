/*
* Memory Operations
* (C) 1999-2009,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
import cstring;
/**
* Zeroize memory
* @param ptr a pointer to memory to zero out
* @param n the number of bytes pointed to by ptr
*/
void zero_mem(void* ptr, size_t n);

/**
* Zeroize memory
* @param ptr a pointer to an array
* @param n the number of Ts pointed to by ptr
*/
void clear_mem(T)(T* ptr, size_t n)
{
	zero_mem(ptr, sizeof(T)*n);
}

/**
* Copy memory
* @param out the destination array
* @param in the source array
* @param n the number of elements of in/out
*/
void copy_mem(T)(T* output, const T* input)
{
	std::memmove(output, input, sizeof(T)*n);
}

/**
* Set memory to a fixed value
* @param ptr a pointer to an array
* @param n the number of Ts pointed to by ptr
* @param val the value to set each ubyte to
*/
void set_mem(T)(T* ptr, size_t n, ubyte val)
{
	std::memset(ptr, val, sizeof(T)*n);
}

/**
* Memory comparison, input insensitive
* @param p1 a pointer to an array
* @param p2 a pointer to another array
* @param n the number of Ts in p1 and p2
* @return true iff p1[i] == p2[i] forall i in [0...n)
*/
bool same_mem(T)(const T* p1, const T* p2, size_t n)
{
	volatile T difference = 0;

	for (size_t i = 0; i != n; ++i)
		difference |= (p1[i] ^ p2[i]);

	return difference == 0;
}