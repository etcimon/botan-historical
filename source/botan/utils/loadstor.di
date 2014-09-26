/*
* Load/Store Operators
* (C) 1999-2007 Jack Lloyd
*	  2007 Yves Jerschow
*
* Distributed under the terms of the botan license.
*/

#include <botan/types.h>
#include <botan/bswap.h>
#include <botan/get_byte.h>
#include <cstring>

#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK

#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)

#define BOTAN_ENDIAN_N2B(x) (x)
#define BOTAN_ENDIAN_B2N(x) (x)

#define BOTAN_ENDIAN_N2L(x) reverse_bytes(x)
#define BOTAN_ENDIAN_L2N(x) reverse_bytes(x)

#elif defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)

#define BOTAN_ENDIAN_N2L(x) (x)
#define BOTAN_ENDIAN_L2N(x) (x)

#define BOTAN_ENDIAN_N2B(x) reverse_bytes(x)
#define BOTAN_ENDIAN_B2N(x) reverse_bytes(x)

#endif

#endif
/**
* Make a ushort from two bytes
* @param i0 the first byte
* @param i1 the second byte
* @return i0 || i1
*/
ushort make_ushort(byte i0, byte i1)
{
	return ((cast(ushort)(i0) << 8) | i1);
}

/**
* Make a uint from four bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @return i0 || i1 || i2 || i3
*/
uint make_uint(byte i0, byte i1, byte i2, byte i3)
{
	return ((cast(uint)(i0) << 24) |
			  (cast(uint)(i1) << 16) |
			  (cast(uint)(i2) <<  8) |
			  (cast(uint)(i3)));
}

/**
* Make a ulong from eight bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @param i4 the fifth byte
* @param i5 the sixth byte
* @param i6 the seventh byte
* @param i7 the eighth byte
* @return i0 || i1 || i2 || i3 || i4 || i5 || i6 || i7
*/
ulong make_ulong(byte i0, byte i1, byte i2, byte i3,
				  byte i4, byte i5, byte i6, byte i7)
{
	return ((cast(ulong)(i0) << 56) |
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
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a big-endian value
*/
 T load_be(T)(in byte* input, size_t off)
{
	in += off * sizeof(T);
	T out = 0;
	for(size_t i = 0; i != sizeof(T); ++i)
		out = (out << 8) | input[i];
	return out;
}

/**
* Load a little-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a litte-endian value
*/
 T load_le(T)(in byte* input, size_t off)
{
	in += off * sizeof(T);
	T out = 0;
	for(size_t i = 0; i != sizeof(T); ++i)
		out = (out << 8) | input[sizeof(T)-1-i];
	return out;
}

/**
* Load a big-endian ushort
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th ushort of in, as a big-endian value
*/
template<>
 ushort load_be(T : ushort)(in byte* input, size_t off)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2B(*(cast(const ushort*)(input) + off));
#else
	in += off * sizeof(ushort);
	return make_ushort(input[0], input[1]);
#endif
}

/**
* Load a little-endian ushort
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th ushort of in, as a little-endian value
*/
template<>
 ushort load_le(T : ushort)(in byte* input, size_t off)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2L(*(cast(const ushort*)(input) + off));
#else
	in += off * sizeof(ushort);
	return make_ushort(input[1], input[0]);
#endif
}

/**
* Load a big-endian uint
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint of in, as a big-endian value
*/
template<>
 uint load_be(T : uint)(in byte* input, size_t off)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2B(*(cast(const uint*)(input) + off));
#else
	in += off * sizeof(uint);
	return make_uint(input[0], input[1], input[2], input[3]);
#endif
}

/**
* Load a little-endian uint
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint of in, as a little-endian value
*/
template<>
 uint load_le(T : uint)(in byte* input, size_t off)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2L(*(cast(const uint*)(input) + off));
#else
	in += off * sizeof(uint);
	return make_uint(input[3], input[2], input[1], input[0]);
#endif
}

/**
* Load a big-endian ulong
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th ulong of in, as a big-endian value
*/
template<>
 ulong load_be(T : ulong)(in byte* input, size_t off)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2B(*(cast(const ulong*)(input) + off));
#else
	in += off * sizeof(ulong);
	return make_ulong(input[0], input[1], input[2], input[3],
							 input[4], input[5], input[6], input[7]);
#endif
}

/**
* Load a little-endian ulong
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th ulong of in, as a little-endian value
*/
template<>
 ulong load_le(T : ulong)(in byte* input, size_t off)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2L(*(cast(const ulong*)(input) + off));
#else
	in += off * sizeof(ulong);
	return make_ulong(input[7], input[6], input[5], input[4],
							 input[3], input[2], input[1], input[0]);
#endif
}

/**
* Load two little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
*/

void load_le(T)(in byte* input, ref T x0, ref T x1)
{
	x0 = load_le!T(input, 0);
	x1 = load_le!T(input, 1);
}

/**
* Load four little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
*/
void load_le(T)(in byte* in,
						 ref T x0, ref T x1, ref T x2, ref T x3)
{
	x0 = load_le!T(input, 0);
	x1 = load_le!T(input, 1);
	x2 = load_le!T(input, 2);
	x3 = load_le!T(input, 3);
}

/**
* Load eight little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
* @param x4 where the fifth word will be written
* @param x5 where the sixth word will be written
* @param x6 where the seventh word will be written
* @param x7 where the eighth word will be written
*/
void load_le(T)(in byte* input,
				  ref T x0, ref T x1, ref T x2, ref T x3,
				  ref T x4, ref T x5, ref T x6, ref T x7)
{
	x0 = load_le!T(input, 0);
	x1 = load_le!T(input, 1);
	x2 = load_le!T(input, 2);
	x3 = load_le!T(input, 3);
	x4 = load_le!T(input, 4);
	x5 = load_le!T(input, 5);
	x6 = load_le!T(input, 6);
	x7 = load_le!T(input, 7);
}

/**
* Load a variable number of little-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
void load_le(T)(T* output,
				  in byte* input,
				  size_t count)
{
#if defined(BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS)
	std::memcpy(output, input, sizeof(T)*count);

#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
	const size_t blocks = count - (count % 4);
	const size_t left = count - blocks;

	for(size_t i = 0; i != blocks; i += 4)
		bswap_4(output + i);

	for(size_t i = 0; i != left; ++i)
		output[blocks+i] = reverse_bytes(output[blocks+i]);
#endif

#else
	for(size_t i = 0; i != count; ++i)
		output[i] = load_le!T(input, i);
#endif
}

/**
* Load two big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
*/
void load_be(T)(in byte* input, ref T x0, ref T x1)
{
	x0 = load_be!T(input, 0);
	x1 = load_be!T(input, 1);
}

/**
* Load four big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
*/
void load_be(T)(in byte* input,
				ref T x0, ref T x1, ref T x2, ref T x3)
{
	x0 = load_be!T(input, 0);
	x1 = load_be!T(input, 1);
	x2 = load_be!T(input, 2);
	x3 = load_be!T(input, 3);
}

/**
* Load eight big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
* @param x4 where the fifth word will be written
* @param x5 where the sixth word will be written
* @param x6 where the seventh word will be written
* @param x7 where the eighth word will be written
*/
void load_be(T)(in byte* input,
				  ref T x0, ref T x1, ref T x2, ref T x3,
				  ref T x4, ref T x5, ref T x6, ref T x7)
{
	x0 = load_be!T(input, 0);
	x1 = load_be!T(input, 1);
	x2 = load_be!T(input, 2);
	x3 = load_be!T(input, 3);
	x4 = load_be!T(input, 4);
	x5 = load_be!T(input, 5);
	x6 = load_be!T(input, 6);
	x7 = load_be!T(input, 7);
}

/**
* Load a variable number of big-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
void load_be(T)(T* output,
						  in byte* input,
						  size_t count)
{
#if defined(BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS)
	std::memcpy(output, input, sizeof(T)*count);

#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
	const size_t blocks = count - (count % 4);
	const size_t left = count - blocks;

	for(size_t i = 0; i != blocks; i += 4)
		bswap_4(output + i);

	for(size_t i = 0; i != left; ++i)
		output[blocks+i] = reverse_bytes(output[blocks+i]);
#endif

#else
	for(size_t i = 0; i != count; ++i)
		output[i] = load_be!T(input, i);
#endif
}

/**
* Store a big-endian ushort
* @param in the input ushort
* @param out the byte array to write to
*/
void store_be(ushort input, byte* output)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(ushort*)(output.ptr) = BOTAN_ENDIAN_B2N(input);
#else
	output[0] = get_byte(0, input);
	output[1] = get_byte(1, input);
#endif
}

/**
* Store a little-endian ushort
* @param in the input ushort
* @param out the byte array to write to
*/
void store_le(ushort input, byte[2] output)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(ushort*)(output) = BOTAN_ENDIAN_L2N(input);
#else
	output[0] = get_byte(1, input);
	output[1] = get_byte(0, input);
#endif
}

/**
* Store a big-endian uint
* @param in the input uint
* @param out the byte array to write to
*/
void store_be(uint in, byte[4] output)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(uint*)(output) = BOTAN_ENDIAN_B2N(input);
#else
	output[0] = get_byte(0, input);
	output[1] = get_byte(1, input);
	output[2] = get_byte(2, input);
	output[3] = get_byte(3, input);
#endif
}

/**
* Store a little-endian uint
* @param in the input uint
* @param out the byte array to write to
*/
void store_le(uint input, byte[4] output)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(uint*)(output) = BOTAN_ENDIAN_L2N(input);
#else
	output[0] = get_byte(3, input);
	output[1] = get_byte(2, input);
	output[2] = get_byte(1, input);
	output[3] = get_byte(0, input);
#endif
}

/**
* Store a big-endian ulong
* @param in the input ulong
* @param out the byte array to write to
*/
void store_be(ulong input, byte[8] output)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(ulong*)(output) = BOTAN_ENDIAN_B2N(input);
#else
	output[0] = get_byte(0, input);
	output[1] = get_byte(1, input);
	output[2] = get_byte(2, input);
	output[3] = get_byte(3, input);
	output[4] = get_byte(4, input);
	output[5] = get_byte(5, input);
	output[6] = get_byte(6, input);
	output[7] = get_byte(7, input);
#endif
}

/**
* Store a little-endian ulong
* @param in the input ulong
* @param out the byte array to write to
*/
void store_le(ulong in, byte[8] output)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(ulong*)(output) = BOTAN_ENDIAN_L2N(input);
#else
	output[0] = get_byte(7, input);
	output[1] = get_byte(6, input);
	output[2] = get_byte(5, input);
	output[3] = get_byte(4, input);
	output[4] = get_byte(3, input);
	output[5] = get_byte(2, input);
	output[6] = get_byte(1, input);
	output[7] = get_byte(0, input);
#endif
}

/**
* Store two little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
*/
void store_le(T)(byte* output, T x0, T x1)
{
	store_le(x0, output + (0 * sizeof(T)));
	store_le(x1, output + (1 * sizeof(T)));
}

/**
* Store two big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
*/
void store_be(T)(ref byte* output, T x0, T x1)
{
	store_be(x0, output + (0 * sizeof(T)));
	store_be(x1, output + (1 * sizeof(T)));
}

/**
* Store four little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
*/
void store_le(T)(byte* output, T x0, T x1, T x2, T x3)
{
	store_le(x0, output + (0 * sizeof(T)));
	store_le(x1, output + (1 * sizeof(T)));
	store_le(x2, output + (2 * sizeof(T)));
	store_le(x3, output + (3 * sizeof(T)));
}

/**
* Store four big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
*/
void store_be(T)(ref byte* output, T x0, T x1, T x2, T x3)
{
	store_be(x0, output + (0 * sizeof(T)));
	store_be(x1, output + (1 * sizeof(T)));
	store_be(x2, output + (2 * sizeof(T)));
	store_be(x3, output + (3 * sizeof(T)));
}

/**
* Store eight little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
* @param x4 the fifth word
* @param x5 the sixth word
* @param x6 the seventh word
* @param x7 the eighth word
*/
void store_le(T)(byte* output, T x0, T x1, T x2, T x3,
								T x4, T x5, T x6, T x7)
{
	store_le(x0, output + (0 * sizeof(T)));
	store_le(x1, output + (1 * sizeof(T)));
	store_le(x2, output + (2 * sizeof(T)));
	store_le(x3, output + (3 * sizeof(T)));
	store_le(x4, output + (4 * sizeof(T)));
	store_le(x5, output + (5 * sizeof(T)));
	store_le(x6, output + (6 * sizeof(T)));
	store_le(x7, output + (7 * sizeof(T)));
}

/**
* Store eight big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
* @param x4 the fifth word
* @param x5 the sixth word
* @param x6 the seventh word
* @param x7 the eighth word
*/
void store_be(T)(byte* output, T x0, T x1, T x2, T x3,
								T x4, T x5, T x6, T x7)
{
	store_be(x0, output + (0 * sizeof(T)));
	store_be(x1, output + (1 * sizeof(T)));
	store_be(x2, output + (2 * sizeof(T)));
	store_be(x3, output + (3 * sizeof(T)));
	store_be(x4, output + (4 * sizeof(T)));
	store_be(x5, output + (5 * sizeof(T)));
	store_be(x6, output + (6 * sizeof(T)));
	store_be(x7, output + (7 * sizeof(T)));
}