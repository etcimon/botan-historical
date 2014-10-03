/*
* OFB Mode
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.ofb;
import botan.internal.xor_buf;
OFB::OFB(BlockCipher cipher) :
	m_cipher(cipher),
	m_buffer(m_cipher.block_size()),
	m_buf_pos(0)
{
}

void OFB::clear()
{
	m_cipher.clear();
	zeroise(m_buffer);
	m_buf_pos = 0;
}

void OFB::key_schedule(in byte* key, size_t length)
{
	m_cipher.set_key(key, key_len);

	// Set a default all-zeros IV
	set_iv(null, 0);
}

string OFB::name() const
{
	return "OFB(" + m_cipher.name() + ")";
}

void OFB::cipher(in byte* input, byte* output)
{
	while(length >= m_buffer.size() - m_buf_pos)
	{
		xor_buf(output, input, &m_buffer[m_buf_pos], m_buffer.size() - m_buf_pos);
		length -= (m_buffer.size() - m_buf_pos);
		input += (m_buffer.size() - m_buf_pos);
		output += (m_buffer.size() - m_buf_pos);
		m_cipher.encrypt(m_buffer);
		m_buf_pos = 0;
	}
	xor_buf(output, input, &m_buffer[m_buf_pos], length);
	m_buf_pos += length;
}

void OFB::set_iv(in byte* iv, size_t iv_len)
{
	if (!valid_iv_length(iv_len))
		throw new Invalid_IV_Length(name(), iv_len);

	zeroise(m_buffer);
	buffer_insert(m_buffer, 0, iv, iv_len);

	m_cipher.encrypt(m_buffer);
	m_buf_pos = 0;
}

}
