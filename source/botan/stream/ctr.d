/*
* CTR-BE Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.ctr;

import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.utils.xor_buf;

/**
* CTR-BE (Counter mode, big-endian)
*/
class CTR_BE : StreamCipher
{
public:
	void cipher(in ubyte* input, ubyte* output)
	{
		while(length >= m_pad.length - m_pad_pos)
		{
			xor_buf(output, input, &m_pad[m_pad_pos], m_pad.length - m_pad_pos);
			length -= (m_pad.length - m_pad_pos);
			input += (m_pad.length - m_pad_pos);
			output += (m_pad.length - m_pad_pos);
			increment_counter();
		}
		xor_buf(output, input, &m_pad[m_pad_pos], length);
		m_pad_pos += length;
	}


	void set_iv(in ubyte* iv, size_t iv_len)
	{
		if (!valid_iv_length(iv_len))
			throw new Invalid_IV_Length(name(), iv_len);
		
		const size_t bs = m_cipher.block_size;
		
		zeroise(m_counter);
		
		buffer_insert(m_counter, 0, iv, iv_len);
		
		// Set m_counter blocks to IV, IV + 1, ... IV + 255
		for (size_t i = 1; i != 256; ++i)
		{
			buffer_insert(m_counter, i*bs, &m_counter[(i-1)*bs], bs);
			
			for (size_t j = 0; j != bs; ++j)
				if (++m_counter[i*bs + (bs - 1 - j)])
					break;
		}
		
		m_cipher.encrypt_n(&m_counter[0], &m_pad[0], 256);
		m_pad_pos = 0;
	}

	bool valid_iv_length(size_t iv_len) const
	{ return (iv_len <= m_cipher.block_size); }

	Key_Length_Specification key_spec() const
	{
		return m_cipher.key_spec();
	}

	@property string name() const
	{
		return ("CTR-BE(" ~ m_cipher.name ~ ")");
	}

	CTR_BE* clone() const
	{ return new CTR_BE(m_cipher.clone()); }

	void clear()
	{
		m_cipher.clear();
		zeroise(m_pad);
		zeroise(m_counter);
		m_pad_pos = 0;
	}

	/**
	* @param cipher the underlying block cipher to use
	*/
	this(BlockCipher ciph)
	{
		m_cipher = ciph;
		m_counter = 256 * m_cipher.block_size;
		m_pad = m_counter.length;
		m_pad_pos = 0;
	}
private:
	void key_schedule(in ubyte* key, size_t length)
	{
		m_cipher.set_key(key, key_len);
		
		// Set a default all-zeros IV
		set_iv(null, 0);
	}

	/*
	* Increment the counter and update the buffer
	*/
	void increment_counter()
	{
		const size_t bs = m_cipher.block_size;
		
		/*
	* Each counter value always needs to be incremented by 256,
	* so we don't touch the lowest ubyte and instead treat it as
	* an increment of one starting with the next ubyte.
	*/
		for (size_t i = 0; i != 256; ++i)
		{
			for (size_t j = 1; j != bs; ++j)
				if (++m_counter[i*bs + (bs - 1 - j)])
					break;
		}
		
		m_cipher.encrypt_n(&m_counter[0], &m_pad[0], 256);
		m_pad_pos = 0;
	}

	Unique!BlockCipher m_cipher;
	SafeVector!ubyte m_counter, m_pad;
	size_t m_pad_pos;
};
