/*
* ANSI X9.19 MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.x919_mac;

import botan.mac.mac;
import botan.block.block_cipher;
import botan.utils.xor_buf;
import std.algorithm;

/**
* DES/3DES-based MAC from ANSI X9.19
*/
class ANSI_X919_MAC : MessageAuthenticationCode
{
public:
	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		m_des1.clear();
		m_des2.clear();
		zeroise(m_state);
		m_position = 0;
	}


	string name() const
	{
		return "X9.19-MAC";
	}

	size_t output_length() const { return 8; }

	MessageAuthenticationCode clone() const
	{
		return new ANSI_X919_MAC(m_des1.clone());
	}

	Key_Length_Specification key_spec() const
	{
		return Key_Length_Specification(8, 16, 8);
	}

	/**
	* @param cipher the underlying block cipher to use
	*/
	this(BlockCipher cipher) 
	{
		m_des1 = cipher;
		m_des2 = m_des1.clone();
		m_state = 8;
		m_position = 0;
		if (cipher.name() != "DES")
			throw new Invalid_Argument("ANSI X9.19 MAC only supports DES");
	}

private:
	/*
	* Update an ANSI X9.19 MAC Calculation
	*/
	void add_data(in ubyte* input, size_t length)
	{
		size_t xored = std.algorithm.min(8 - m_position, length);
		xor_buf(&m_state[m_position], input, xored);
		m_position += xored;
		
		if (m_position < 8) return;
		
		m_des1.encrypt(m_state);
		input += xored;
		length -= xored;
		while(length >= 8)
		{
			xor_buf(m_state, input, 8);
			m_des1.encrypt(m_state);
			input += 8;
			length -= 8;
		}
		
		xor_buf(m_state, input, length);
		m_position = length;
	}

	/*
	* Finalize an ANSI X9.19 MAC Calculation
	*/
	void final_result(ubyte* mac)
	{
		if (m_position)
			m_des1.encrypt(m_state);
		m_des2.decrypt(&m_state[0], mac);
		m_des1.encrypt(mac);
		zeroise(m_state);
		m_position = 0;
	}


	/*
	* ANSI X9.19 MAC Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		m_des1.set_key(key, 8);
		
		if (length == 16)
			key += 8;
		
		m_des2.set_key(key, 8);
	}


	Unique!BlockCipher m_des1, m_des2;
	SafeVector!ubyte m_state;
	size_t m_position;
};