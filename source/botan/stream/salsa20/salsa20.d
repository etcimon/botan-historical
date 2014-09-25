/*
* Salsa20 / XSalsa20
* (C) 1999-2010,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/salsa20.h>
#include <botan/loadstor.h>
#include <botan/rotate.h>
#include <botan/internal/xor_buf.h>
namespace {

#define SALSA20_QUARTER_ROUND(x1, x2, x3, x4)	 \
	do {														\
		x2 ^= rotate_left(x1 + x4,  7);				\
		x3 ^= rotate_left(x2 + x1,  9);				\
		x4 ^= rotate_left(x3 + x2, 13);				\
		x1 ^= rotate_left(x4 + x3, 18);				\
} while(0)

/*
* Generate HSalsa20 cipher stream (for XSalsa20 IV setup)
*/
void hsalsa20(uint output[8], const uint input[16])
{
	uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
			 x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
			 x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
			 x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

	for(size_t i = 0; i != 10; ++i)
	{
		SALSA20_QUARTER_ROUND(x00, x04, x08, x12);
		SALSA20_QUARTER_ROUND(x05, x09, x13, x01);
		SALSA20_QUARTER_ROUND(x10, x14, x02, x06);
		SALSA20_QUARTER_ROUND(x15, x03, x07, x11);

		SALSA20_QUARTER_ROUND(x00, x01, x02, x03);
		SALSA20_QUARTER_ROUND(x05, x06, x07, x04);
		SALSA20_QUARTER_ROUND(x10, x11, x08, x09);
		SALSA20_QUARTER_ROUND(x15, x12, x13, x14);
	}

	output[0] = x00;
	output[1] = x05;
	output[2] = x10;
	output[3] = x15;
	output[4] = x06;
	output[5] = x07;
	output[6] = x08;
	output[7] = x09;
}

/*
* Generate Salsa20 cipher stream
*/
void salsa20(byte output[64], const uint input[16])
{
	uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
			 x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
			 x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
			 x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

	for(size_t i = 0; i != 10; ++i)
	{
		SALSA20_QUARTER_ROUND(x00, x04, x08, x12);
		SALSA20_QUARTER_ROUND(x05, x09, x13, x01);
		SALSA20_QUARTER_ROUND(x10, x14, x02, x06);
		SALSA20_QUARTER_ROUND(x15, x03, x07, x11);

		SALSA20_QUARTER_ROUND(x00, x01, x02, x03);
		SALSA20_QUARTER_ROUND(x05, x06, x07, x04);
		SALSA20_QUARTER_ROUND(x10, x11, x08, x09);
		SALSA20_QUARTER_ROUND(x15, x12, x13, x14);
	}

	store_le(x00 + input[ 0], output + 4 *  0);
	store_le(x01 + input[ 1], output + 4 *  1);
	store_le(x02 + input[ 2], output + 4 *  2);
	store_le(x03 + input[ 3], output + 4 *  3);
	store_le(x04 + input[ 4], output + 4 *  4);
	store_le(x05 + input[ 5], output + 4 *  5);
	store_le(x06 + input[ 6], output + 4 *  6);
	store_le(x07 + input[ 7], output + 4 *  7);
	store_le(x08 + input[ 8], output + 4 *  8);
	store_le(x09 + input[ 9], output + 4 *  9);
	store_le(x10 + input[10], output + 4 * 10);
	store_le(x11 + input[11], output + 4 * 11);
	store_le(x12 + input[12], output + 4 * 12);
	store_le(x13 + input[13], output + 4 * 13);
	store_le(x14 + input[14], output + 4 * 14);
	store_le(x15 + input[15], output + 4 * 15);
}

}

#undef SALSA20_QUARTER_ROUND

/*
* Combine cipher stream with message
*/
void Salsa20::cipher(in byte[] input, ref byte[] output)
{
	while(length >= m_buffer.size() - m_position)
	{
		xor_buf(out, in, &m_buffer[m_position], m_buffer.size() - m_position);
		length -= (m_buffer.size() - m_position);
		in += (m_buffer.size() - m_position);
		out += (m_buffer.size() - m_position);
		salsa20(&m_buffer[0], &m_state[0]);

		++m_state[8];
		m_state[9] += (m_state[8] == 0);

		m_position = 0;
	}

	xor_buf(out, in, &m_buffer[m_position], length);

	m_position += length;
}

/*
* Salsa20 Key Schedule
*/
void Salsa20::key_schedule(in byte[] key)
{
	static const uint TAU[] =
	{ 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

	static const uint SIGMA[] =
	{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

	const uint* CONSTANTS = (length == 16) ? TAU : SIGMA;

	m_state.resize(16);
	m_buffer.resize(64);

	m_state[0] = CONSTANTS[0];
	m_state[5] = CONSTANTS[1];
	m_state[10] = CONSTANTS[2];
	m_state[15] = CONSTANTS[3];

	m_state[1] = load_le<uint>(key, 0);
	m_state[2] = load_le<uint>(key, 1);
	m_state[3] = load_le<uint>(key, 2);
	m_state[4] = load_le<uint>(key, 3);

	if(length == 32)
		key += 16;

	m_state[11] = load_le<uint>(key, 0);
	m_state[12] = load_le<uint>(key, 1);
	m_state[13] = load_le<uint>(key, 2);
	m_state[14] = load_le<uint>(key, 3);

	m_position = 0;

	const byte ZERO[8] = { 0 };
	set_iv(ZERO, sizeof(ZERO));
}

/*
* Return the name of this type
*/
void Salsa20::set_iv(in byte[] iv, size_t length)
{
	if(!valid_iv_length(length))
		throw new Invalid_IV_Length(name(), length);

	if(length == 8)
	{
		// Salsa20
		m_state[6] = load_le<uint>(iv, 0);
		m_state[7] = load_le<uint>(iv, 1);
	}
	else
	{
		// XSalsa20
		m_state[6] = load_le<uint>(iv, 0);
		m_state[7] = load_le<uint>(iv, 1);
		m_state[8] = load_le<uint>(iv, 2);
		m_state[9] = load_le<uint>(iv, 3);

		secure_vector<uint> hsalsa(8);
		hsalsa20(&hsalsa[0], &m_state[0]);

		m_state[ 1] = hsalsa[0];
		m_state[ 2] = hsalsa[1];
		m_state[ 3] = hsalsa[2];
		m_state[ 4] = hsalsa[3];
		m_state[ 6] = load_le<uint>(iv, 4);
		m_state[ 7] = load_le<uint>(iv, 5);
		m_state[11] = hsalsa[4];
		m_state[12] = hsalsa[5];
		m_state[13] = hsalsa[6];
		m_state[14] = hsalsa[7];
	}

	m_state[8] = 0;
	m_state[9] = 0;

	salsa20(&m_buffer[0], &m_state[0]);
	++m_state[8];
	m_state[9] += (m_state[8] == 0);

	m_position = 0;
}

/*
* Return the name of this type
*/
string Salsa20::name() const
{
	return "Salsa20";
}

/*
* Clear memory of sensitive data
*/
void Salsa20::clear()
{
	zap(m_state);
	zap(m_buffer);
	m_position = 0;
}

}
