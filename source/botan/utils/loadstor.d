/*
* Load/Store Operators
* (C) 1999-2007 Jack Lloyd
*      2007 Yves Jerschow
*
* Distributed under the terms of the botan license.
*/
module botan.utils.loadstor;

import botan.utils.types;
import botan.utils.bswap;
import botan.utils.get_byte;
import std.bitmanip;

nothrow:
pure:

/**
* Make a ushort from two bytes
* @param i0 = the first ubyte
* @param i1 = the second ubyte
* @return i0 || i1
*/
ushort make_ushort(ubyte i0, ubyte i1)
{
    return ((cast(ushort)(i0) << 8) | i1);
}

/**
* Make a uint from four bytes
* @param i0 = the first ubyte
* @param i1 = the second ubyte
* @param i2 = the third ubyte
* @param i3 = the fourth ubyte
* @return i0 || i1 || i2 || i3
*/
uint make_uint(ubyte i0, ubyte i1, ubyte i2, ubyte i3)
{
    return ((cast(uint)(i0) << 24) |
            (cast(uint)(i1) << 16) |
            (cast(uint)(i2) <<  8) |
            (cast(uint)(i3)));
}

/**
* Make a ulong from eight bytes
* @param i0 = the first ubyte
* @param i1 = the second ubyte
* @param i2 = the third ubyte
* @param i3 = the fourth ubyte
* @param i4 = the fifth ubyte
* @param i5 = the sixth ubyte
* @param i6 = the seventh ubyte
* @param i7 = the eighth ubyte
* @return i0 || i1 || i2 || i3 || i4 || i5 || i6 || i7
*/
ulong make_ulong(ubyte i0, ubyte i1, ubyte i2, ubyte i3,
                  ubyte i4, ubyte i5, ubyte i6, ubyte i7)
{
    return     ((cast(ulong)(i0) << 56) |
             (cast(ulong)(i1) << 48) |
             (cast(ulong)(i2) << 40) |
             (cast(ulong)(i3) << 32) |
             (cast(ulong)(i4) << 24) |
             (cast(ulong)(i5) << 16) |
             (cast(ulong)(i6) <<  8) |
             (cast(ulong)(i7)));
}

/**
* Load a big-endian word
* @param input = a pointer to some bytes
* @param off = an offset into the array
* @return off'th T of in, as a big-endian value
*/
T loadBigEndian(T)(in ubyte* input, size_t off)
{
    input += off * T.sizeof;
    T output = 0;
    for (size_t i = 0; i != T.sizeof; ++i)
        output = (output << 8) | input[i];
    return output;
}

/**
* Load a little-endian word
* @param input = a pointer to some bytes
* @param off = an offset into the array
* @return off'th T of in, as a litte-endian value
*/
T loadLittleEndian(T)(in ubyte* input, size_t off)
{
    input += off * T.sizeof;
    T output = 0;
    for (size_t i = 0; i != T.sizeof; ++i)
        output = (output << 8) | input[T.sizeof-1-i];
    return output;
}

/**
* Load a big-endian ushort
* @param input = a pointer to some bytes
* @param off = an offset into the array
* @return off'th ushort of in, as a big-endian value
*/
ushort loadBigEndian(T : ushort)(in ubyte* input, size_t off)
{
    return *cast(ushort*) nativeToBigEndian!ushort(*( (cast(const ushort*) input) + off));
}

/**
* Load a little-endian ushort
* @param input = a pointer to some bytes
* @param off = an offset into the array
* @return off'th ushort of in, as a little-endian value
*/
ushort loadLittleEndian(T : ushort)(in ubyte* input, size_t off)
{
    return *cast(ushort*) nativeToLittleEndian!ushort(*((cast(const ushort*) input) + off));
}

/**
* Load a big-endian uint
* @param input = a pointer to some bytes
* @param off = an offset into the array
* @return off'th uint of in, as a big-endian value
*/
uint loadBigEndian(T : uint)(in ubyte* input, size_t off)
{
    return *cast(uint*) nativeToBigEndian!uint(*((cast(const uint*) input) + off));
}

/**
* Load a little-endian uint
* @param input = a pointer to some bytes
* @param off = an offset into the array
* @return off'th uint of in, as a little-endian value
*/

uint loadLittleEndian(T : uint)(in ubyte* input, size_t off)
{
    return *cast(uint*) nativeToLittleEndian!uint(*( (cast(const uint*) input) + off));
}

/**
* Load a big-endian ulong
* @param input = a pointer to some bytes
* @param off = an offset into the array
* @return off'th ulong of in, as a big-endian value
*/
ulong loadBigEndian(T : ulong)(in ubyte* input, size_t off)
{
    return *cast(ulong*) nativeToBigEndian!ulong(*( (cast(const ulong*) input) + off));
    
}

/**
* Load a little-endian ulong
* @param input = a pointer to some bytes
* @param off = an offset into the array
* @return off'th ulong of in, as a little-endian value
*/
ulong loadLittleEndian(T : ulong)(in ubyte* input, size_t off)
{
    return *cast(ulong*) nativeToLittleEndian!ulong(*( (cast(const ulong*) input) + off));
}

/**
* Load two little-endian words
* @param input = a pointer to some bytes
* @param x0 = where the first word will be written
* @param x1 = where the second word will be written
*/
void loadLittleEndian(T)(in ubyte* input, ref T x0, ref T x1)
{
    x0 = loadLittleEndian!T(input, 0);
    x1 = loadLittleEndian!T(input, 1);
}

/**
* Load four little-endian words
* @param input = a pointer to some bytes
* @param x0 = where the first word will be written
* @param x1 = where the second word will be written
* @param x2 = where the third word will be written
* @param x3 = where the fourth word will be written
*/
void loadLittleEndian(T)(in ubyte* input,
                ref T x0, ref T x1, ref T x2, ref T x3)
{
    x0 = loadLittleEndian!T(input, 0);
    x1 = loadLittleEndian!T(input, 1);
    x2 = loadLittleEndian!T(input, 2);
    x3 = loadLittleEndian!T(input, 3);
}

/**
* Load eight little-endian words
* @param input = a pointer to some bytes
* @param x0 = where the first word will be written
* @param x1 = where the second word will be written
* @param x2 = where the third word will be written
* @param x3 = where the fourth word will be written
* @param x4 = where the fifth word will be written
* @param x5 = where the sixth word will be written
* @param x6 = where the seventh word will be written
* @param x7 = where the eighth word will be written
*/
void loadLittleEndian(T)(in ubyte* input,
                  ref T x0, ref T x1, ref T x2, ref T x3,
                  ref T x4, ref T x5, ref T x6, ref T x7)
{
    x0 = loadLittleEndian!T(input, 0);
    x1 = loadLittleEndian!T(input, 1);
    x2 = loadLittleEndian!T(input, 2);
    x3 = loadLittleEndian!T(input, 3);
    x4 = loadLittleEndian!T(input, 4);
    x5 = loadLittleEndian!T(input, 5);
    x6 = loadLittleEndian!T(input, 6);
    x7 = loadLittleEndian!T(input, 7);
}

/**
* Load a variable number of little-endian words
* @param output = the output array of words
* @param input = the input array of bytes
* @param count = how many words are in in
*/
void loadLittleEndian(T)(T* output, in ubyte* input, size_t count)
{
    static if (BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS) {
        import std.c.string : memcpy;
        memcpy(output, input, T.sizeof*count);

        version(BigEndian) {
            
            const size_t blocks = count - (count % 4);
            const size_t left = count - blocks;

            for (size_t i = 0; i != blocks; i += 4)
                bswap4(*cast(T[4]*) (output + i));

            foreach (size_t i; 0 .. left)
                output[blocks+i] = reverseBytes(output[blocks+i]);
        }
    } else {
        foreach (size_t i; 0 .. count)
            output[i] = loadLittleEndian!T(input, i);
    }
}

/**
* Load two big-endian words
* @param input = a pointer to some bytes
* @param x0 = where the first word will be written
* @param x1 = where the second word will be written
*/
void loadBigEndian(T)(in ubyte* input, ref T x0, ref T x1)
{
    x0 = loadBigEndian!T(input, 0);
    x1 = loadBigEndian!T(input, 1);
}

/**
* Load four big-endian words
* @param input = a pointer to some bytes
* @param x0 = where the first word will be written
* @param x1 = where the second word will be written
* @param x2 = where the third word will be written
* @param x3 = where the fourth word will be written
*/
void loadBigEndian(T)(in ubyte* input, ref T x0, ref T x1, ref T x2, ref T x3)
{
    x0 = loadBigEndian!T(input, 0);
    x1 = loadBigEndian!T(input, 1);
    x2 = loadBigEndian!T(input, 2);
    x3 = loadBigEndian!T(input, 3);
}

/**
* Load eight big-endian words
* @param input = a pointer to some bytes
* @param x0 = where the first word will be written
* @param x1 = where the second word will be written
* @param x2 = where the third word will be written
* @param x3 = where the fourth word will be written
* @param x4 = where the fifth word will be written
* @param x5 = where the sixth word will be written
* @param x6 = where the seventh word will be written
* @param x7 = where the eighth word will be written
*/
void loadBigEndian(T)(in ubyte* input,
                ref T x0, ref T x1, ref T x2, ref T x3,
                ref T x4, ref T x5, ref T x6, ref T x7)
{
    x0 = loadBigEndian!T(input, 0);
    x1 = loadBigEndian!T(input, 1);
    x2 = loadBigEndian!T(input, 2);
    x3 = loadBigEndian!T(input, 3);
    x4 = loadBigEndian!T(input, 4);
    x5 = loadBigEndian!T(input, 5);
    x6 = loadBigEndian!T(input, 6);
    x7 = loadBigEndian!T(input, 7);
}

/**
* Load a variable number of big-endian words
* @param output = the output array of words
* @param input = the input array of bytes
* @param count = how many words are in in
*/
void loadBigEndian(T)(T* output, in ubyte* input, size_t count)
{
    static if (BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS) {
        import std.c.string : memcpy;
        memcpy(output, input, T.sizeof*count);

        version(LittleEndian) {
            
            const size_t blocks = count - (count % 4);
            const size_t left = count - blocks;

            for (size_t i = 0; i != blocks; i += 4)
                bswap4(*cast(T[4]*) (output + i));

            foreach (size_t i; 0 .. left)
                output[blocks+i] = reverseBytes(output[blocks+i]);
        }

    } else {
        foreach (size_t i; 0 .. count)
            output[i] = loadBigEndian!T(input, i);
    }
}

/**
* Store a big-endian ushort
* @param input = the input ushort
* @param output = the ubyte array to write to
*/
void storeBigEndian(ushort input, ref ubyte[2] output)
{
    *cast(ushort*) output = bigEndianToNative!ushort(*cast(ubyte[2]*) input);
    
}

/**
* Store a little-endian ushort
* @param input = the input ushort
* @param output = the ubyte array to write to
*/
void storeLittleEndian(ushort input, ref ubyte[2] output)
{
    *cast(ushort*) output = littleEndianToNative!ushort(*cast(ubyte[2]*) input);
    
}

/**
* Store a big-endian uint
* @param input = the input uint
* @param output = the ubyte array to write to
*/
void storeBigEndian(uint input, ref ubyte[4] output)
{
    *cast(uint*) output = bigEndianToNative!uint(*cast(ubyte[4]*) input);
    
}

/**
* Store a little-endian uint
* @param input = the input uint
* @param output = the ubyte array to write to
*/
void storeLittleEndian(uint input, ref ubyte[4] output)
{
    *cast(uint*) output = littleEndianToNative!uint(*cast(ubyte[4]*) input);

}

/**
* Store a big-endian ulong
* @param input = the input ulong
* @param output = the ubyte array to write to
*/
void storeBigEndian(ulong input, ref ubyte[8] output)
{
    *cast(ulong*) output = bigEndianToNative!ulong(*cast(ubyte[8]*) input);
}

/**
* Store a little-endian ulong
* @param input = the input ulong
* @param output = the ubyte array to write to
*/
void storeLittleEndian(ulong input, ref ubyte[8] output)
{
    *cast(ulong*) output = littleEndianToNative!ulong(*cast(ubyte[8]*) input);
}

/**
* Store a little-endian ulong
* @param input = the input ulong
* @param output = the ubyte array to write to
*/
void storeLittleEndian(T)(T input, ubyte* output)
{
    storeLittleEndian(input, *cast(ubyte[T.sizeof]*) output);
}

/**
* Store a big-endian ulong
* @param input = the input ulong
* @param output = the ubyte array to write to
*/
void storeBigEndian(T)(T input, ubyte* output)
{
    storeBigEndian(input, *cast(ubyte[T.sizeof]*) output);
}

/**
* Store two little-endian words
* @param output = the output ubyte array
* @param x0 = the first word
* @param x1 = the second word
*/
void storeLittleEndian(T)(ubyte* output, T x0, T x1)
{
    storeLittleEndian(x0, output + (0 * T.sizeof));
    storeLittleEndian(x1, output + (1 * T.sizeof));
}

/**
* Store two big-endian words
* @param output = the output ubyte array
* @param x0 = the first word
* @param x1 = the second word
*/
void storeBigEndian(T)(ref ubyte* output, T x0, T x1)
{
    storeBigEndian(x0, output + (0 * T.sizeof));
    storeBigEndian(x1, output + (1 * T.sizeof));
}

/**
* Store four little-endian words
* @param output = the output ubyte array
* @param x0 = the first word
* @param x1 = the second word
* @param x2 = the third word
* @param x3 = the fourth word
*/
void storeLittleEndian(T)(ubyte* output, T x0, T x1, T x2, T x3)
{
    storeLittleEndian(x0, output + (0 * T.sizeof));
    storeLittleEndian(x1, output + (1 * T.sizeof));
    storeLittleEndian(x2, output + (2 * T.sizeof));
    storeLittleEndian(x3, output + (3 * T.sizeof));
}

/**
* Store four big-endian words
* @param output = the output ubyte array
* @param x0 = the first word
* @param x1 = the second word
* @param x2 = the third word
* @param x3 = the fourth word
*/
void storeBigEndian(T)(ref ubyte* output, T x0, T x1, T x2, T x3)
{
    storeBigEndian(x0, output + (0 * T.sizeof));
    storeBigEndian(x1, output + (1 * T.sizeof));
    storeBigEndian(x2, output + (2 * T.sizeof));
    storeBigEndian(x3, output + (3 * T.sizeof));
}

/**
* Store eight little-endian words
* @param output = the output ubyte array
* @param x0 = the first word
* @param x1 = the second word
* @param x2 = the third word
* @param x3 = the fourth word
* @param x4 = the fifth word
* @param x5 = the sixth word
* @param x6 = the seventh word
* @param x7 = the eighth word
*/
void storeLittleEndian(T)(ubyte* output, T x0, T x1, T x2, T x3,
                                T x4, T x5, T x6, T x7)
{
    storeLittleEndian(x0, output + (0 * T.sizeof));
    storeLittleEndian(x1, output + (1 * T.sizeof));
    storeLittleEndian(x2, output + (2 * T.sizeof));
    storeLittleEndian(x3, output + (3 * T.sizeof));
    storeLittleEndian(x4, output + (4 * T.sizeof));
    storeLittleEndian(x5, output + (5 * T.sizeof));
    storeLittleEndian(x6, output + (6 * T.sizeof));
    storeLittleEndian(x7, output + (7 * T.sizeof));
}

/**
* Store eight big-endian words
* @param output = the output ubyte array
* @param x0 = the first word
* @param x1 = the second word
* @param x2 = the third word
* @param x3 = the fourth word
* @param x4 = the fifth word
* @param x5 = the sixth word
* @param x6 = the seventh word
* @param x7 = the eighth word
*/
void storeBigEndian(T)(ubyte* output, T x0, T x1, T x2, T x3,
                                T x4, T x5, T x6, T x7)
{
    storeBigEndian(x0, output + (0 * T.sizeof));
    storeBigEndian(x1, output + (1 * T.sizeof));
    storeBigEndian(x2, output + (2 * T.sizeof));
    storeBigEndian(x3, output + (3 * T.sizeof));
    storeBigEndian(x4, output + (4 * T.sizeof));
    storeBigEndian(x5, output + (5 * T.sizeof));
    storeBigEndian(x6, output + (6 * T.sizeof));
    storeBigEndian(x7, output + (7 * T.sizeof));
}