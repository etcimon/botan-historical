/*
* Secure Memory Buffers
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.memory.zeroize;

import botan.utils.mem_ops;
import std.algorithm;
import botan.utils.types;
import botan.utils.memory.memory;
import botan.utils.memory.noswap;
import std.traits : ReturnType;

alias SecureAllocator = ZeroizeAllocator!VulnerableAllocator;

final class ZeroizeAllocator(Base : Allocator)
{
    private {
        shared NoSwapAllocator m_primary;
        Base m_secondary;
    }

    this() {
        m_primary = new shared NoSwapAllocator;
    }

    void[] alloc(size_t n)
    {
        if (void[] p = m_primary.alloc(n))
            return p;
        void[] p = m_secondary.alloc(n);
        clearMem(p.ptr, n);
        return p;
    }

    void free(void[] mem)
    {
        clearMem(mem.ptr, mem.length);
        if (m_primary.free(mem))
            return;
        m_secondary.free(mem);
    }

}

alias SecureVector(T) = Vector!(T, SecureAllocator);

Vector!(T, VulnerableAllocator) unlock(T, ALLOC)(Vector!(T, ALLOC) input)
    if (is(ALLOC == SecureAllocator))
{
    Vector!(T, VulnerableAllocator) output = Vector!T(input.length);
    copyMem(output.ptr, input.ptr, input.length);
    return output;
}

size_t bufferInsert(T, Alloc)(Vector!(T, Alloc) buf, size_t buf_offset, in T* input, size_t input_length)
{
    const size_t to_copy = min(input_length, buf.length - buf_offset);
    copyMem(&buf[buf_offset], input, to_copy);
    return to_copy;
}

size_t bufferInsert(T, Alloc, Alloc2)(Vector!(T, Alloc) buf, size_t buf_offset, in Vector!( T, Alloc2 ) input)
{
    const size_t to_copy = min(input.length, buf.length - buf_offset);
    copyMem(&buf[buf_offset], input.ptr, to_copy);
    return to_copy;
}

/**
* Zeroise the values; length remains unchanged
* @param vec = the vector to zeroise
*/
void zeroise(T, Alloc)(Vector!(T, Alloc) vec)
{
    clearMem(vec.ptr, vec.length);
}

/**
* Zeroise the values then free the memory
* @param vec = the vector to zeroise and free
*/
void zap(T, Alloc)(Vector!(T, Alloc) vec)
{
    import std.traits : hasIndirections;
    static if (!hasIndirections!T)
        zeroise(vec);
    vec.clear();
}