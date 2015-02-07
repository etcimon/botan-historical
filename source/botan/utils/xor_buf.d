/*
* XOR operations
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.xor_buf;

import botan.constants;
import botan.utils.types;
pure {
    /**
    * XOR arrays. Postcondition output[i] = input[i] ^ output[i] forall i = 0...length
    * @param output = the input/output buffer
    * @param input = the read-only input buffer
    * @param length = the length of the buffers
    */
    void xorBuf(T)(T* output, const(T)* input, size_t length)
    {
        while (length >= 8)
        {
            output[0 .. 8] ^= input[0 .. 8];

            output += 8; input += 8; length -= 8;
        }

        output[0 .. length] ^= input[0 .. length];
    }

    /**
    * XOR arrays. Postcondition output[i] = input[i] ^ in2[i] forall i = 0...length
    * @param output = the output buffer
    * @param input = the first input buffer
    * @param in2 = the second output buffer
    * @param length = the length of the three buffers
    */
    void xorBuf(T)(T* output,
                   const(T)* input,
                   const(T)* input2,
                   size_t length)
    {
        while (length >= 8)
        {
            output[0 .. 8] = input[0 .. 8] ^ input2[0 .. 8];

            input += 8; input2 += 8; output += 8; length -= 8;
        }

        output[0 .. length] = input[0 .. length] ^ input2[0 .. length];
    }

    version(none) {
        static if (BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK) {

            void xorBuf(ubyte* output, const(ubyte)* input, size_t length)
            {
                while (length >= 8)
                {
                    *cast(ulong*)(output) ^= *cast(const ulong*)(input);
                    output += 8; input += 8; length -= 8;
                }

                output[0 .. length] ^= input[0 .. length];
            }

            void xorBuf(ubyte* output,
                         const(ubyte)* input,
                         const(ubyte)* input2,
                         size_t length)
            {
                while (length >= 8)
                {
                    *cast(ulong*)(output) = (*cast(const ulong*) input) ^ (*cast(const ulong*)input2);

                    input += 8; input2 += 8; output += 8; length -= 8;
                }

                output[0 .. length] = input[0 .. length] ^ input2[0 .. length];
            }

        }
    }
}
void xorBuf(Alloc, Alloc2)(ref Vector!( ubyte, Alloc ) output,
                                   ref Vector!( ubyte, Alloc2 ) input,
                                   size_t n)
{
    xorBuf(output.ptr, input.ptr, n);
}

void xorBuf(Alloc)(ref Vector!( ubyte, Alloc ) output,
                   const(ubyte)* input,
                   size_t n)
{
    xorBuf(output.ptr, input, n);
}

void xorBuf(Alloc, Alloc2)(ref Vector!( ubyte, Alloc ) output,
                           const(ubyte)* input,
                           ref Vector!( ubyte, Alloc2 ) input2,
                            size_t n)
{
    xorBuf(output.ptr, input, input2.ptr, n);
}
