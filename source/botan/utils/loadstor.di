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
* Make a u16bit from two bytes
* @param i0 the first byte
* @param i1 the second byte
* @return i0 || i1
*/
inline u16bit make_u16bit(byte i0, byte i1)
{
	return ((cast(u16bit)(i0) << 8) | i1);
}

/**
* Make a uint from four bytes
* @param i0 the first byte
* @param i1 the second byte
* @param i2 the third byte
* @param i3 the fourth byte
* @return i0 || i1 || i2 || i3
*/
inline uint make_uint(byte i0, byte i1, byte i2, byte i3)
{
	return ((cast(uint)(i0) << 24) |
			  (cast(uint)(i1) << 16) |
			  (cast(uint)(i2) <<  8) |
			  (cast(uint)(i3)));
}

/**
* Make a uint from eight bytes
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
inline u64bit make_u64bit(byte i0, byte i1, byte i2, byte i3,
								  byte i4, byte i5, byte i6, byte i7)
	 {
	return ((cast(u64bit)(i0) << 56) |
			  (cast(u64bit)(i1) << 48) |
			  (cast(u64bit)(i2) << 40) |
			  (cast(u64bit)(i3) << 32) |
			  (cast(u64bit)(i4) << 24) |
			  (cast(u64bit)(i5) << 16) |
			  (cast(u64bit)(i6) <<  8) |
			  (cast(u64bit)(i7)));
	 }

/**
* Load a big-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a big-endian value
*/
template<typename T>
inline T load_be(in byte[] input)
{
	in += off * sizeof(T);
	T out = 0;
	for(size_t i = 0; i != sizeof(T); ++i)
		out = (out << 8) | in[i];
	return out;
}

/**
* Load a little-endian word
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th T of in, as a litte-endian value
*/
template<typename T>
inline T load_le(in byte[] input)
{
	in += off * sizeof(T);
	T out = 0;
	for(size_t i = 0; i != sizeof(T); ++i)
		out = (out << 8) | in[sizeof(T)-1-i];
	return out;
}

/**
* Load a big-endian u16bit
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th u16bit of in, as a big-endian value
*/
template<>
inline u16bit load_be<u16bit>(in byte[] input)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2B(*(cast(const u16bit*)(input) + off));
#else
	in += off * sizeof(u16bit);
	return make_u16bit(in[0], in[1]);
#endif
}

/**
* Load a little-endian u16bit
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th u16bit of in, as a little-endian value
*/
template<>
inline u16bit load_le<u16bit>(in byte[] input)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2L(*(cast(const u16bit*)(input) + off));
#else
	in += off * sizeof(u16bit);
	return make_u16bit(in[1], in[0]);
#endif
}

/**
* Load a big-endian uint
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint of in, as a big-endian value
*/
template<>
inline uint load_be<uint>(in byte[] input)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2B(*(cast(const uint*)(input) + off));
#else
	in += off * sizeof(uint);
	return make_uint(in[0], in[1], in[2], in[3]);
#endif
}

/**
* Load a little-endian uint
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th uint of in, as a little-endian value
*/
template<>
inline uint load_le<uint>(in byte[] input)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2L(*(cast(const uint*)(input) + off));
#else
	in += off * sizeof(uint);
	return make_uint(in[3], in[2], in[1], in[0]);
#endif
}

/**
* Load a big-endian u64bit
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th u64bit of in, as a big-endian value
*/
template<>
inline u64bit load_be<u64bit>(in byte[] input)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2B(*(cast(const u64bit*)(input) + off));
#else
	in += off * sizeof(u64bit);
	return make_u64bit(in[0], in[1], in[2], in[3],
							 in[4], in[5], in[6], in[7]);
#endif
}

/**
* Load a little-endian u64bit
* @param in a pointer to some bytes
* @param off an offset into the array
* @return off'th u64bit of in, as a little-endian value
*/
template<>
inline u64bit load_le<u64bit>(in byte[] input)
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	return BOTAN_ENDIAN_N2L(*(cast(const u64bit*)(input) + off));
#else
	in += off * sizeof(u64bit);
	return make_u64bit(in[7], in[6], in[5], in[4],
							 in[3], in[2], in[1], in[0]);
#endif
}

/**
* Load two little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
*/
template<typename T>
inline void load_le(in byte[] in, T& x0, T& x1)
{
	x0 = load_le<T>(input, 0);
	x1 = load_le<T>(input, 1);
}

/**
* Load four little-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
*/
template<typename T>
inline void load_le(in byte[] in,
						  T& x0, T& x1, T& x2, T& x3)
{
	x0 = load_le<T>(input, 0);
	x1 = load_le<T>(input, 1);
	x2 = load_le<T>(input, 2);
	x3 = load_le<T>(input, 3);
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
template<typename T>
inline void load_le(in byte[] in,
						  T& x0, T& x1, T& x2, T& x3,
						  T& x4, T& x5, T& x6, T& x7)
{
	x0 = load_le<T>(input, 0);
	x1 = load_le<T>(input, 1);
	x2 = load_le<T>(input, 2);
	x3 = load_le<T>(input, 3);
	x4 = load_le<T>(input, 4);
	x5 = load_le<T>(input, 5);
	x6 = load_le<T>(input, 6);
	x7 = load_le<T>(input, 7);
}

/**
* Load a variable number of little-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
template<typename T>
inline void load_le(T out[],
						  in byte[] in,
						  size_t count)
{
#if defined(BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS)
	std::memcpy(out, in, sizeof(T)*count);

#if defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
	const size_t blocks = count - (count % 4);
	const size_t left = count - blocks;

	for(size_t i = 0; i != blocks; i += 4)
		bswap_4(out + i);

	for(size_t i = 0; i != left; ++i)
		out[blocks+i] = reverse_bytes(out[blocks+i]);
#endif

#else
	for(size_t i = 0; i != count; ++i)
		out[i] = load_le<T>(input, i);
#endif
}

/**
* Load two big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
*/
template<typename T>
inline void load_be(in byte[] in, T& x0, T& x1)
{
	x0 = load_be<T>(input, 0);
	x1 = load_be<T>(input, 1);
}

/**
* Load four big-endian words
* @param in a pointer to some bytes
* @param x0 where the first word will be written
* @param x1 where the second word will be written
* @param x2 where the third word will be written
* @param x3 where the fourth word will be written
*/
template<typename T>
inline void load_be(in byte[] in,
						  T& x0, T& x1, T& x2, T& x3)
{
	x0 = load_be<T>(input, 0);
	x1 = load_be<T>(input, 1);
	x2 = load_be<T>(input, 2);
	x3 = load_be<T>(input, 3);
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
template<typename T>
inline void load_be(in byte[] in,
						  T& x0, T& x1, T& x2, T& x3,
						  T& x4, T& x5, T& x6, T& x7)
{
	x0 = load_be<T>(input, 0);
	x1 = load_be<T>(input, 1);
	x2 = load_be<T>(input, 2);
	x3 = load_be<T>(input, 3);
	x4 = load_be<T>(input, 4);
	x5 = load_be<T>(input, 5);
	x6 = load_be<T>(input, 6);
	x7 = load_be<T>(input, 7);
}

/**
* Load a variable number of big-endian words
* @param out the output array of words
* @param in the input array of bytes
* @param count how many words are in in
*/
template<typename T>
inline void load_be(T out[],
						  in byte[] in,
						  size_t count)
{
#if defined(BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS)
	std::memcpy(out, in, sizeof(T)*count);

#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
	const size_t blocks = count - (count % 4);
	const size_t left = count - blocks;

	for(size_t i = 0; i != blocks; i += 4)
		bswap_4(out + i);

	for(size_t i = 0; i != left; ++i)
		out[blocks+i] = reverse_bytes(out[blocks+i]);
#endif

#else
	for(size_t i = 0; i != count; ++i)
		out[i] = load_be<T>(input, i);
#endif
}

/**
* Store a big-endian u16bit
* @param in the input u16bit
* @param out the byte array to write to
*/
inline void store_be(u16bit in, byte out[2])
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(u16bit*)(out) = BOTAN_ENDIAN_B2N(input);
#else
	out[0] = get_byte(0, input);
	out[1] = get_byte(1, input);
#endif
}

/**
* Store a little-endian u16bit
* @param in the input u16bit
* @param out the byte array to write to
*/
inline void store_le(u16bit in, byte out[2])
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(u16bit*)(out) = BOTAN_ENDIAN_L2N(input);
#else
	out[0] = get_byte(1, input);
	out[1] = get_byte(0, input);
#endif
}

/**
* Store a big-endian uint
* @param in the input uint
* @param out the byte array to write to
*/
inline void store_be(uint in, byte out[4])
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(uint*)(out) = BOTAN_ENDIAN_B2N(input);
#else
	out[0] = get_byte(0, input);
	out[1] = get_byte(1, input);
	out[2] = get_byte(2, input);
	out[3] = get_byte(3, input);
#endif
}

/**
* Store a little-endian uint
* @param in the input uint
* @param out the byte array to write to
*/
inline void store_le(uint in, byte out[4])
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(uint*)(out) = BOTAN_ENDIAN_L2N(input);
#else
	out[0] = get_byte(3, input);
	out[1] = get_byte(2, input);
	out[2] = get_byte(1, input);
	out[3] = get_byte(0, input);
#endif
}

/**
* Store a big-endian u64bit
* @param in the input u64bit
* @param out the byte array to write to
*/
inline void store_be(u64bit in, byte out[8])
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(u64bit*)(out) = BOTAN_ENDIAN_B2N(input);
#else
	out[0] = get_byte(0, input);
	out[1] = get_byte(1, input);
	out[2] = get_byte(2, input);
	out[3] = get_byte(3, input);
	out[4] = get_byte(4, input);
	out[5] = get_byte(5, input);
	out[6] = get_byte(6, input);
	out[7] = get_byte(7, input);
#endif
}

/**
* Store a little-endian u64bit
* @param in the input u64bit
* @param out the byte array to write to
*/
inline void store_le(u64bit in, byte out[8])
{
#if BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK
	*cast(u64bit*)(out) = BOTAN_ENDIAN_L2N(input);
#else
	out[0] = get_byte(7, input);
	out[1] = get_byte(6, input);
	out[2] = get_byte(5, input);
	out[3] = get_byte(4, input);
	out[4] = get_byte(3, input);
	out[5] = get_byte(2, input);
	out[6] = get_byte(1, input);
	out[7] = get_byte(0, input);
#endif
}

/**
* Store two little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
*/
template<typename T>
inline void store_le(ref byte[] output, T x0, T x1)
{
	store_le(x0, out + (0 * sizeof(T)));
	store_le(x1, out + (1 * sizeof(T)));
}

/**
* Store two big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
*/
template<typename T>
inline void store_be(ref byte[] output, T x0, T x1)
{
	store_be(x0, out + (0 * sizeof(T)));
	store_be(x1, out + (1 * sizeof(T)));
}

/**
* Store four little-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
*/
template<typename T>
inline void store_le(ref byte[] output, T x0, T x1, T x2, T x3)
{
	store_le(x0, out + (0 * sizeof(T)));
	store_le(x1, out + (1 * sizeof(T)));
	store_le(x2, out + (2 * sizeof(T)));
	store_le(x3, out + (3 * sizeof(T)));
}

/**
* Store four big-endian words
* @param out the output byte array
* @param x0 the first word
* @param x1 the second word
* @param x2 the third word
* @param x3 the fourth word
*/
template<typename T>
inline void store_be(ref byte[] output, T x0, T x1, T x2, T x3)
{
	store_be(x0, out + (0 * sizeof(T)));
	store_be(x1, out + (1 * sizeof(T)));
	store_be(x2, out + (2 * sizeof(T)));
	store_be(x3, out + (3 * sizeof(T)));
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
template<typename T>
inline void store_le(ref byte[] output, T x0, T x1, T x2, T x3,
											T x4, T x5, T x6, T x7)
{
	store_le(x0, out + (0 * sizeof(T)));
	store_le(x1, out + (1 * sizeof(T)));
	store_le(x2, out + (2 * sizeof(T)));
	store_le(x3, out + (3 * sizeof(T)));
	store_le(x4, out + (4 * sizeof(T)));
	store_le(x5, out + (5 * sizeof(T)));
	store_le(x6, out + (6 * sizeof(T)));
	store_le(x7, out + (7 * sizeof(T)));
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
template<typename T>
inline void store_be(ref byte[] output, T x0, T x1, T x2, T x3,
											T x4, T x5, T x6, T x7)
{
	store_be(x0, out + (0 * sizeof(T)));
	store_be(x1, out + (1 * sizeof(T)));
	store_be(x2, out + (2 * sizeof(T)));
	store_be(x3, out + (3 * sizeof(T)));
	store_be(x4, out + (4 * sizeof(T)));
	store_be(x5, out + (5 * sizeof(T)));
	store_be(x6, out + (6 * sizeof(T)));
	store_be(x7, out + (7 * sizeof(T)));
}