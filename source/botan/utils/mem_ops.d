/*
* Memory Operations
* (C) 1999-2009,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.mem_ops;
import botan.utils.types;

/**
* Zeroise memory
* @param ptr = a pointer to an array
* @param n = the number of Ts pointed to by ptr
*/
void clearMem(T)(T* ptr, size_t n)
{
    ubyte[] mem = (cast(ubyte*)ptr)[0 .. T.sizeof*n];
    foreach (ref ubyte ub; mem) ub = 0;
}

/**
* Copy memory
* @param output = the destination array
* @param input = the source array
* @param n = the number of elements of in/out
*/
void copyMem(T)(T* output, in T* input, in size_t n)
{
    import std.c.string : memmove;
    memmove(output, input, T.sizeof*n);
}

/**
* Set memory to a fixed value
* @param ptr = a pointer to an array
* @param n = the number of Ts pointed to by ptr
* @param val = the value to set each ubyte to
*/
void setMem(T)(T* ptr, size_t n, ubyte val)
{
    import std.c.string : memset;
    memset(ptr, val, T.sizeof*n);
}

/**
* Memory comparison, input insensitive
* @param p1 = a pointer to an array
* @param p2 = a pointer to another array
* @param n = the number of Ts in p1 and p2
* @return true iff p1[i] == p2[i] forall i in [0...n)
*/
bool sameMem(T)(in T* p1, in T* p2, in size_t n)
{
    return ((cast(const(ubyte)*)p1)[0 .. n] is (cast(const(ubyte)*)p2)[0 .. n]);
}