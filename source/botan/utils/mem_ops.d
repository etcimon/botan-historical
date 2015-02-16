/*
* Memory Operations
* (C) 1999-2009,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.mem_ops;
import botan.utils.types;
import std.algorithm : min;


Vector!T unlock(T, ALLOC)(auto const ref Vector!(T, ALLOC) input)
    if (is(ALLOC == SecureMem))
{
    return Vector!T(input.ptr[0 .. input.length]);
}

RefCounted!(Vector!T) unlock(T, ALLOC)(auto const ref RefCounted!(Vector!(T, ALLOC), ALLOC) input)
    if (is(ALLOC == SecureMem))
{
    return RefCounted!(Vector!T)(input[]);
}

/**
* Zeroise the values then free the memory
* @param vec = the vector to zeroise and free
*/
void zap(T, Alloc)(ref Vector!(T, Alloc) vec)
{
    import std.traits : hasIndirections;
    static if (!hasIndirections!T && !is(Alloc == SecureMem))
        zeroise(vec);
    vec.clear();
}

size_t bufferInsert(T, Alloc)(ref Vector!(T, Alloc) buf, size_t buf_offset, in T* input, size_t input_length)
{
    import std.algorithm : max;
    const size_t to_copy = min(input_length, buf.length - buf_offset);
    buf.resize(max(buf.length, buf_offset + to_copy));
    copyMem(buf.ptr + buf_offset, input, to_copy);
    return to_copy;
}

size_t bufferInsert(T, Alloc, Alloc2)(ref Vector!(T, Alloc) buf, size_t buf_offset, const ref Vector!(T, Alloc2) input)
{
    import std.algorithm : max;
    const size_t to_copy = min(input.length, buf.length - buf_offset);
    buf.resize(max(buf.length, buf_offset + to_copy));
    copyMem(&buf[buf_offset], input.ptr, to_copy);
    return to_copy;
}

pure:

/**
* Zeroise memory
* @param ptr = a pointer to an array
* @param n = the number of Ts pointed to by ptr
*/
void clearMem(T)(T* ptr, size_t n)
{
    setMem(ptr,n,0);
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
    //logDebug("memset ops: ", cast(void*)ptr, " L:", T.sizeof*n);
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
    return ((cast(const(ubyte)*)p1)[0 .. n] == (cast(const(ubyte)*)p2)[0 .. n]);
}


/**
* Zeroise the values; length remains unchanged
* @param vec = the vector to zeroise
*/
void zeroise(T, Alloc)(ref Vector!(T, Alloc) vec)
{
    clearMem(vec.ptr, vec.length);
}

void zeroise(T)(T[] mem) {
    clearMem(mem.ptr, mem.length);
}

