/*
* Salsa20 / XSalsa20
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.salsa20;

import botan.stream.stream_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.xor_buf;

/**
* DJB's Salsa20 (and XSalsa20)
*/
class Salsa20 : StreamCipher
{
public:
	/*
	* Combine cipher stream with message
	*/
	void cipher(in ubyte* input, ubyte* output)
	{
		while(length >= m_buffer.length - m_position)
		{
			xor_buf(output, input, &m_buffer[m_position], m_buffer.length - m_position);
			length -= (m_buffer.length - m_position);
			input += (m_buffer.length - m_position);
			output += (m_buffer.length - m_position);
			salsa20(&m_buffer[0], &m_state[0]);
			
			++m_state[8];
			m_state[9] += (m_state[8] == 0);
			
			m_position = 0;
		}
		
		xor_buf(output, input, &m_buffer[m_position], length);
		
		m_position += length;
	}


	/*
	* Return the name of this type
	*/
	void set_iv(in ubyte* iv, size_t length)
	{
		if (!valid_iv_length(length))
			throw new Invalid_IV_Length(name(), length);
		
		if (length == 8)
		{
			// Salsa20
			m_state[6] = load_le!uint(iv, 0);
			m_state[7] = load_le!uint(iv, 1);
		}
		else
		{
			// XSalsa20
			m_state[6] = load_le!uint(iv, 0);
			m_state[7] = load_le!uint(iv, 1);
			m_state[8] = load_le!uint(iv, 2);
			m_state[9] = load_le!uint(iv, 3);
			
			SafeVector!uint hsalsa(8);
			hsalsa20(&hsalsa[0], &m_state[0]);
			
			m_state[ 1] = hsalsa[0];
			m_state[ 2] = hsalsa[1];
			m_state[ 3] = hsalsa[2];
			m_state[ 4] = hsalsa[3];
			m_state[ 6] = load_le!uint(iv, 4);
			m_state[ 7] = load_le!uint(iv, 5);
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

	bool valid_iv_length(size_t iv_len) const
	{ return (iv_len == 8 || iv_len == 24); }

	Key_Length_Specification key_spec() const
	{
		return Key_Length_Specification(16, 32, 16);
	}

	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		zap(m_state);
		zap(m_buffer);
		m_position = 0;
	}

	/*
	* Return the name of this type
	*/
	string name() const
	{
		return "Salsa20";
	}

	StreamCipher clone() const { return new Salsa20; }
private:
	/*
	* Salsa20 Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		immutable uint[] TAU =
		{ 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };
		
		immutable uint[] SIGMA =
		{ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
		
		const uint* CONSTANTS = (length == 16) ? TAU : SIGMA;
		
		m_state.resize(16);
		m_buffer.resize(64);
		
		m_state[0] = CONSTANTS[0];
		m_state[5] = CONSTANTS[1];
		m_state[10] = CONSTANTS[2];
		m_state[15] = CONSTANTS[3];
		
		m_state[1] = load_le!uint(key, 0);
		m_state[2] = load_le!uint(key, 1);
		m_state[3] = load_le!uint(key, 2);
		m_state[4] = load_le!uint(key, 3);
		
		if (length == 32)
			key += 16;
		
		m_state[11] = load_le!uint(key, 0);
		m_state[12] = load_le!uint(key, 1);
		m_state[13] = load_le!uint(key, 2);
		m_state[14] = load_le!uint(key, 3);
		
		m_position = 0;
		
		const ubyte[8] ZERO;
		set_iv(ZERO, (ZERO).sizeof);
	}

	SafeVector!uint m_state;
	SafeVector!ubyte m_buffer;
	size_t m_position;
};


private:

/*
* Generate HSalsa20 cipher stream (for XSalsa20 IV setup)
*/
void hsalsa20(uint[8] output, const uint[16] input)
{
	uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
		x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
		x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
		x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];
	
	for (size_t i = 0; i != 10; ++i)
	{
		mixin(	SALSA20_QUARTER_ROUND!(x00, x04, x08, x12)() ~
				SALSA20_QUARTER_ROUND!(x05, x09, x13, x01)() ~
				SALSA20_QUARTER_ROUND!(x10, x14, x02, x06)() ~
				SALSA20_QUARTER_ROUND!(x15, x03, x07, x11)() ~
				
				SALSA20_QUARTER_ROUND!(x00, x01, x02, x03)() ~
				SALSA20_QUARTER_ROUND!(x05, x06, x07, x04)() ~
				SALSA20_QUARTER_ROUND!(x10, x11, x08, x09)() ~
				SALSA20_QUARTER_ROUND!(x15, x12, x13, x14)()
		      );
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
void salsa20(ubyte[64] output, const uint[16] input)
{
	uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
		x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
		x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
		x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];
	
	for (size_t i = 0; i != 10; ++i)
	{
		mixin(	SALSA20_QUARTER_ROUND!(x00, x04, x08, x12)() ~
				SALSA20_QUARTER_ROUND!(x05, x09, x13, x01)() ~
				SALSA20_QUARTER_ROUND!(x10, x14, x02, x06)() ~
				SALSA20_QUARTER_ROUND!(x15, x03, x07, x11)() ~

				SALSA20_QUARTER_ROUND!(x00, x01, x02, x03)() ~
				SALSA20_QUARTER_ROUND!(x05, x06, x07, x04)() ~
				SALSA20_QUARTER_ROUND!(x10, x11, x08, x09)() ~
		     	SALSA20_QUARTER_ROUND!(x15, x12, x13, x14)()
		      );
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

string SALSA20_QUARTER_ROUND(alias _x1, alias _x2, alias _x3, alias _x4)()
{
	alias x1 = __traits(identifier, _x1).stringof;
	alias x2 = __traits(identifier, _x2).stringof;
	alias x3 = __traits(identifier, _x3).stringof;
	alias x4 = __traits(identifier, _x4).stringof;
	
	return x2 ~ ` ^= rotate_left(` ~ x1 ~ ` + ` ~ x4 ~ `,  7);
			` ~ x3 ~ ` ^= rotate_left(` ~ x2 ~ ` + ` ~ x1 ~ `,  9);
			` ~ x4 ~ ` ^= rotate_left(` ~ x3 ~ ` + ` ~ x2 ~ `, 13);
			` ~ x1 ~ ` ^= rotate_left(` ~ x4 ~ ` + ` ~ x3 ~ `, 18);`;
}