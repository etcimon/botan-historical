/*
* Memory Operations
* (C) 1999-2009,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.mem_ops;
import botan.utils.types;
/**
* Zeroize memory
* @param ptr a pointer to memory to zero out
* @param n the number of bytes pointed to by ptr
*/
void zero_mem(void* ptr, size_t n)
{
	ptr[0 .. n] = 0;
}

/**
* Zeroize memory
* @param ptr a pointer to an array
* @param n the number of Ts pointed to by ptr
*/
void clear_mem(T)(T* ptr, size_t n)
{
	ptr[0 .. T.sizeof*n] = 0;
}

/**
* Copy memory
* @param output the destination array
* @param input the source array
* @param n the number of elements of in/out
*/
void copy_mem(T)(T* output, in T* input, in size_t n)
{
	import std.c.string : memmove;
	memmove(output, input, T.sizeof*n);
}

/**
* Set memory to a fixed value
* @param ptr a pointer to an array
* @param n the number of Ts pointed to by ptr
* @param val the value to set each ubyte to
*/
void set_mem(T)(T* ptr, size_t n, ubyte val)
{
	import std.c.string : memset;
	memset(ptr, val, T.sizeof*n);
}

/**
* Memory comparison, input insensitive
* @param p1 a pointer to an array
* @param p2 a pointer to another array
* @param n the number of Ts in p1 and p2
* @return true iff p1[i] == p2[i] forall i in [0...n)
*/
bool same_mem(T)(in T* p1, in T* p2, in size_t n)
{
	return ((cast(ubyte*)p1)[0 .. n] is (cast(ubyte*)p2)[0 .. n]);
}