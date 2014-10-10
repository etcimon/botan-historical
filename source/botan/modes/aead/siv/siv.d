/*
* SIV Mode Encryption
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.siv;
import botan.cmac;
import botan.ctr;
import botan.parsing;
import botan.internal.xor_buf;
import std.algorithm;
SIV_Mode::SIV_Mode(BlockCipher cipher) :
	m_name(cipher.name() ~ "/SIV"),
	m_ctr(new CTR_BE(cipher.clone())),
	m_cmac(new CMAC(cipher))
{
}

void SIV_Mode::clear()
{
	m_ctr.reset();
	m_nonce.clear();
	m_msg_buf.clear();
	m_ad_macs.clear();
}

string SIV_Mode::name() const
{
	return m_name;
}

bool SIV_Mode::valid_nonce_length(size_t) const
{
	return true;
}

size_t SIV_Mode::update_granularity() const
{
	/*
	This value does not particularly matter as regardless SIV_Mode::update
	buffers all input, so in theory this could be 1. However as for instance
	Transformation_Filter creates update_granularity() ubyte buffers, use a
	somewhat large size to avoid bouncing on a tiny buffer.
	*/
	return 128;
}

Key_Length_Specification SIV_Mode::key_spec() const
{
	return m_cmac.key_spec().multiple(2);
}

void SIV_Mode::key_schedule(in ubyte* key, size_t length)
{
	const size_t keylen = length / 2;
	m_cmac.set_key(key, keylen);
	m_ctr.set_key(key + keylen, keylen);
	m_ad_macs.clear();
}

void SIV_Mode::set_associated_data_n(size_t n, in ubyte* ad, size_t length)
{
	if (n >= m_ad_macs.size())
		m_ad_macs.resize(n+1);

	m_ad_macs[n] = m_cmac.process(ad, length);
}

SafeVector!ubyte SIV_Mode::start(in ubyte* nonce, size_t nonce_len)
{
	if (!valid_nonce_length(nonce_len))
		throw new Invalid_IV_Length(name(), nonce_len);

	if (nonce_len)
		m_nonce = m_cmac.process(nonce, nonce_len);
	else
		m_nonce.clear();

	m_msg_buf.clear();

	return SafeVector!ubyte();
}

void SIV_Mode::update(SafeVector!ubyte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	ubyte* buf = &buffer[offset];

	m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
	buffer.resize(offset); // truncate msg
}

SafeVector!ubyte SIV_Mode::S2V(const ubyte* text, size_t text_len)
{
	const ubyte[16] zero;

	SafeVector!ubyte V = cmac().process(zero, 16);

	for (size_t i = 0; i != m_ad_macs.size(); ++i)
	{
		V = CMAC::poly_double(V);
		V ^= m_ad_macs[i];
	}

	if (m_nonce.size())
	{
		V = CMAC::poly_double(V);
		V ^= m_nonce;
	}

	if (text_len < 16)
	{
		V = CMAC::poly_double(V);
		xor_buf(&V[0], text, text_len);
		V[text_len] ^= 0x80;
		return cmac().process(V);
	}

	cmac().update(text, text_len - 16);
	xor_buf(&V[0], &text[text_len - 16], 16);
	cmac().update(V);

	return cmac().flush();
}

void SIV_Mode::set_ctr_iv(SafeVector!ubyte V)
{
	V[8] &= 0x7F;
	V[12] &= 0x7F;

	ctr().set_iv(&V[0], V.size());
}

void SIV_Encryption::finish(SafeVector!ubyte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");

	buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

	SafeVector!ubyte V = S2V(&buffer[offset], buffer.size() - offset);

	buffer.insert(buffer.begin() + offset, V.begin(), V.end());

	set_ctr_iv(V);
	ctr().cipher1(&buffer[offset + V.size()], buffer.size() - offset - V.size());
}

void SIV_Decryption::finish(SafeVector!ubyte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");

	buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

	const size_t sz = buffer.size() - offset;

	BOTAN_ASSERT(sz >= tag_size(), "We have the tag");

	SafeVector!ubyte V(&buffer[offset], &buffer[offset + 16]);

	set_ctr_iv(V);

	ctr().cipher(&buffer[offset + V.size()],
					 &buffer[offset],
					 buffer.size() - offset - V.size());

	SafeVector!ubyte T = S2V(&buffer[offset], buffer.size() - offset - V.size());

	if (T != V)
		throw new Integrity_Failure("SIV tag check failed");

	buffer.resize(buffer.size() - tag_size());
}

}
