/*
* HKDF
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/hkdf.h>
string HKDF::name() const
{
	return "HKDF(" + m_prf->name() + ")";
}

void HKDF::clear()
{
	m_extractor->clear();
	m_prf->clear();
}

void HKDF::start_extract(in byte[] salt, size_t salt_len)
{
	m_extractor->set_key(salt, salt_len);
}

void HKDF::extract(in byte[] input, size_t input_len)
{
	m_extractor->update(input, input_len);
}

void HKDF::finish_extract()
{
	m_prf->set_key(m_extractor->flush());
}

void HKDF::expand(byte output[], size_t output_len,
						in byte[] info, size_t info_len)
{
	if(output_len > m_prf->output_length() * 255)
		throw new std::invalid_argument("HKDF requested output too large");

	byte counter = 1;

	SafeVector!byte T;

	while(output_len)
	{
		m_prf->update(T);
		m_prf->update(info, info_len);
		m_prf->update(counter++);
		T = m_prf->flush();

		const size_t to_write = std::min(T.size(), output_len);
		copy_mem(&output[0], &T[0], to_write);
		output += to_write;
		output_len -= to_write;
	}
}

}
