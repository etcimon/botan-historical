/*
* CBC-MAC
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.cbc_mac;
import botan.mac.mac;
import botan.block.block_cipher;
import botan.internal.xor_buf;
import std.algorithm;

/**
* CBC-MAC
*/
class CBC_MAC : MessageAuthenticationCode
{
public:
	/*
	* Return the name of this type
	*/
	string name() const
	{
		return "CBC-MAC(" ~ m_cipher.name() ~ ")";
	}

	/*
	* Return a clone of this object
	*/
	MessageAuthenticationCode clone() const
	{
		return new CBC_MAC(m_cipher.clone());
	}

	size_t output_length() const { return m_cipher.block_size(); }

	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		m_cipher.clear();
		zeroise(m_state);
		m_position = 0;
	}

	Key_Length_Specification key_spec() const
	{
		return m_cipher.key_spec();
	}

	/**
	* @param cipher the underlying block cipher to use
	*/
	this(BlockCipher cipher)
	{
		m_cipher = cipher;
		m_state = cipher.block_size();
	}


private:
	/*
* Update an CBC-MAC Calculation
*/
	void add_data(in ubyte* input, size_t length)
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
	void final_result(ubyte* mac)
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
	void key_schedule(in ubyte* key, size_t length)
	{
		m_cipher.set_key(key, length);
	}
	


	Unique!BlockCipher m_cipher;
	SafeVector!ubyte m_state;
	size_t m_position = 0;
};