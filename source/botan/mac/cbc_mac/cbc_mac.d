/*
* CBC-MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.cbc_mac;
import botan.internal.xor_buf;
import algorithm;
/*
* Update an CBC-MAC Calculation
*/
void CBC_MAC::add_data(in ubyte* input, size_t length)
{
	size_t xored = std.algorithm.min(output_length() - m_position, length);
	xor_buf(&m_state[m_position], input, xored);
	m_position += xored;

	if (m_position < output_length())
		return;

	m_cipher.encrypt(m_state);
	input += xored;
	length -= xored;
	while(length >= output_length())
	{
		xor_buf(m_state, input, output_length());
		m_cipher.encrypt(m_state);
		input += output_length();
		length -= output_length();
	}

	xor_buf(m_state, input, length);
	m_position = length;
}

/*
* Finalize an CBC-MAC Calculation
*/
void CBC_MAC::final_result(ubyte mac[])
{
	if (m_position)
		m_cipher.encrypt(m_state);

	copy_mem(mac, &m_state[0], m_state.size());
	zeroise(m_state);
	m_position = 0;
}

/*
* CBC-MAC Key Schedule
*/
void CBC_MAC::key_schedule(in ubyte* key, size_t length)
{
	m_cipher.set_key(key, length);
}

/*
* Clear memory of sensitive data
*/
void CBC_MAC::clear()
{
	m_cipher.clear();
	zeroise(m_state);
	m_position = 0;
}

/*
* Return the name of this type
*/
string CBC_MAC::name() const
{
	return "CBC-MAC(" ~ m_cipher.name() ~ ")";
}

/*
* Return a clone of this object
*/
MessageAuthenticationCode CBC_MAC::clone() const
{
	return new CBC_MAC(m_cipher.clone());
}

/*
* CBC-MAC Constructor
*/
CBC_MAC::CBC_MAC(BlockCipher cipher) :
	m_cipher(cipher), m_state(cipher.block_size())
{
}

}
