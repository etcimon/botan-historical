/*
* Counter mode
* (C) 1999-2011,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/ctr.h>
#include <botan/internal/xor_buf.h>
CTR_BE::CTR_BE(BlockCipher* ciph) :
	m_cipher(ciph),
	m_counter(256 * m_cipher->block_size()),
	m_pad(m_counter.size()),
	m_pad_pos(0)
{
}

void CTR_BE::clear()
{
	m_cipher->clear();
	zeroise(m_pad);
	zeroise(m_counter);
	m_pad_pos = 0;
}

void CTR_BE::key_schedule(in byte* key, size_t length)
{
	m_cipher->set_key(key, key_len);

	// Set a default all-zeros IV
	set_iv(null, 0);
}

string CTR_BE::name() const
{
	return ("CTR-BE(" + m_cipher->name() + ")");
}

void CTR_BE::cipher(in byte* input, byte* output)
{
	while(length >= m_pad.size() - m_pad_pos)
	{
		xor_buf(output, input, &m_pad[m_pad_pos], m_pad.size() - m_pad_pos);
		length -= (m_pad.size() - m_pad_pos);
		input += (m_pad.size() - m_pad_pos);
		output += (m_pad.size() - m_pad_pos);
		increment_counter();
	}
	xor_buf(output, input, &m_pad[m_pad_pos], length);
	m_pad_pos += length;
}

void CTR_BE::set_iv(in byte* iv, size_t iv_len)
{
	if(!valid_iv_length(iv_len))
		throw new Invalid_IV_Length(name(), iv_len);

	const size_t bs = m_cipher->block_size();

	zeroise(m_counter);

	buffer_insert(m_counter, 0, iv, iv_len);

	// Set m_counter blocks to IV, IV + 1, ... IV + 255
	for(size_t i = 1; i != 256; ++i)
	{
		buffer_insert(m_counter, i*bs, &m_counter[(i-1)*bs], bs);

		for(size_t j = 0; j != bs; ++j)
			if(++m_counter[i*bs + (bs - 1 - j)])
				break;
	}

	m_cipher->encrypt_n(&m_counter[0], &m_pad[0], 256);
	m_pad_pos = 0;
}

/*
* Increment the counter and update the buffer
*/
void CTR_BE::increment_counter()
{
	const size_t bs = m_cipher->block_size();

	/*
	* Each counter value always needs to be incremented by 256,
	* so we don't touch the lowest byte and instead treat it as
	* an increment of one starting with the next byte.
	*/
	for(size_t i = 0; i != 256; ++i)
	{
		for(size_t j = 1; j != bs; ++j)
			if(++m_counter[i*bs + (bs - 1 - j)])
				break;
	}

	m_cipher->encrypt_n(&m_counter[0], &m_pad[0], 256);
	m_pad_pos = 0;
}

}
