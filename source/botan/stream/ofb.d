/*
* OFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.ofb;

import botan.stream.stream_cipher;
import botan.block.block_cipher;
import botan.utils.xor_buf;
/**
* Output Feedback Mode
*/
class OFB : StreamCipher
{
public:
	void cipher(in ubyte* input, ubyte* output)
	{
		while(length >= m_buffer.length - m_buf_pos)
		{
			xor_buf(output, input, &m_buffer[m_buf_pos], m_buffer.length - m_buf_pos);
			length -= (m_buffer.length - m_buf_pos);
			input += (m_buffer.length - m_buf_pos);
			output += (m_buffer.length - m_buf_pos);
			m_cipher.encrypt(m_buffer);
			m_buf_pos = 0;
		}
		xor_buf(output, input, &m_buffer[m_buf_pos], length);
		m_buf_pos += length;
	}

	void set_iv(in ubyte* iv, size_t iv_len)
	{
		if (!valid_iv_length(iv_len))
			throw new Invalid_IV_Length(name(), iv_len);
		
		zeroise(m_buffer);
		buffer_insert(m_buffer, 0, iv, iv_len);
		
		m_cipher.encrypt(m_buffer);
		m_buf_pos = 0;
	}

	bool valid_iv_length(size_t iv_len) const
	{ return (iv_len <= m_cipher.block_size()); }

	Key_Length_Specification key_spec() const
	{
		return m_cipher.key_spec();
	}

	string name() const
	{
		return "OFB(" ~ m_cipher.name() ~ ")";
	}

	OFB* clone() const
	{ return new OFB(m_cipher.clone()); }

	void clear()
	{
		m_cipher.clear();
		zeroise(m_buffer);
		m_buf_pos = 0;
	}

	/**
	* @param cipher the underlying block cipher to use
	*/
	this(BlockCipher cipher)
	{
		m_cipher = cipher;
		m_buffer = m_cipher.block_size();
		m_buf_pos = 0;
	}
private:
	void key_schedule(in ubyte* key, size_t length)
	{
		m_cipher.set_key(key, key_len);
		
		// Set a default all-zeros IV
		set_iv(null, 0);
	}

	Unique!BlockCipher m_cipher;
	SafeVector!ubyte m_buffer;
	size_t m_buf_pos;
};