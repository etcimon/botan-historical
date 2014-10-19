/*
* ChaCha
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.chacha;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.internal.xor_buf;
void ChaCha::chacha(ubyte output[64], const uint input[16])
{
	uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
			 x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
			 x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
			 x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];

#define CHACHA_QUARTER_ROUND(a, b, c, d)	\
	do {												\
	a += b; d ^= a; d = rotate_left(d, 16); \
	c += d; b ^= c; b = rotate_left(b, 12); \
	a += b; d ^= a; d = rotate_left(d, 8);  \
	c += d; b ^= c; b = rotate_left(b, 7);  \
} while(0)

	for (size_t i = 0; i != 10; ++i)
	{
		CHACHA_QUARTER_ROUND(x00, x04, x08, x12);
		CHACHA_QUARTER_ROUND(x01, x05, x09, x13);
		CHACHA_QUARTER_ROUND(x02, x06, x10, x14);
		CHACHA_QUARTER_ROUND(x03, x07, x11, x15);

		CHACHA_QUARTER_ROUND(x00, x05, x10, x15);
		CHACHA_QUARTER_ROUND(x01, x06, x11, x12);
		CHACHA_QUARTER_ROUND(x02, x07, x08, x13);
		CHACHA_QUARTER_ROUND(x03, x04, x09, x14);
	}

#undef CHACHA_QUARTER_ROUND

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

/*
* Combine cipher stream with message
*/
void ChaCha::cipher(in ubyte* input, ubyte* output)
{
	while(length >= m_buffer.length - m_position)
	{
		xor_buf(output, input, &m_buffer[m_position], m_buffer.length - m_position);
		length -= (m_buffer.length - m_position);
		input += (m_buffer.length - m_position);
		output += (m_buffer.length - m_position);
		chacha(&m_buffer[0], &m_state[0]);

		++m_state[12];
		m_state[13] += (m_state[12] == 0);

		m_position = 0;
	}

	xor_buf(output, input, &m_buffer[m_position], length);

	m_position += length;
}

/*
* ChaCha Key Schedule
*/
void ChaCha::key_schedule(in ubyte* key, size_t length)
{
	immutable uint[] TAU =
	{ 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

	immutable uint[] SIGMA =
	{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

	const uint* CONSTANTS = (length == 16) ? TAU : SIGMA;

	m_state.resize(16);
	m_buffer.resize(64);

	m_state[0] = CONSTANTS[0];
	m_state[1] = CONSTANTS[1];
	m_state[2] = CONSTANTS[2];
	m_state[3] = CONSTANTS[3];

	m_state[4] = load_le!uint(key, 0);
	m_state[5] = load_le!uint(key, 1);
	m_state[6] = load_le!uint(key, 2);
	m_state[7] = load_le!uint(key, 3);

	if (length == 32)
		key += 16;

	m_state[8] = load_le!uint(key, 0);
	m_state[9] = load_le!uint(key, 1);
	m_state[10] = load_le!uint(key, 2);
	m_state[11] = load_le!uint(key, 3);

	m_position = 0;

	const ubyte[8] ZERO;
	set_iv(ZERO, sizeof(ZERO));
}

/*
* Return the name of this type
*/
void ChaCha::set_iv(in ubyte* iv, size_t length)
{
	if (!valid_iv_length(length))
		throw new Invalid_IV_Length(name(), length);

	m_state[12] = 0;
	m_state[13] = 0;

	m_state[14] = load_le!uint(iv, 0);
	m_state[15] = load_le!uint(iv, 1);

	chacha(&m_buffer[0], &m_state[0]);
	++m_state[12];
	m_state[13] += (m_state[12] == 0);

	m_position = 0;
}

/*
* Return the name of this type
*/
string ChaCha::name() const
{
	return "ChaCha";
}

/*
* Clear memory of sensitive data
*/
void ChaCha::clear()
{
	zap(m_state);
	zap(m_buffer);
	m_position = 0;
}

}
