/*
* EAX Mode Encryption
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.eax;
import botan.cmac;
import botan.ctr;
import botan.parsing;
import botan.internal.xor_buf;
import algorithm;
namespace {

/*
* EAX MAC-based PRF
*/
SafeVector!ubyte eax_prf(ubyte tag, size_t block_size,
						MessageAuthenticationCode mac,
						in ubyte* input,
						size_t length)
{
	for (size_t i = 0; i != block_size - 1; ++i)
		mac.update(0);
	mac.update(tag);
	mac.update(input, length);
	return mac.flush();
}

}

/*
* EAX_Mode Constructor
*/
EAX_Mode::EAX_Mode(BlockCipher cipher, size_t tag_size) :
	m_tag_size(tag_size ? tag_size : cipher.block_size()),
	m_cipher(cipher),
	m_ctr(new CTR_BE(m_cipher.clone())),
	m_cmac(new CMAC(m_cipher.clone()))
{
	if (m_tag_size < 8 || m_tag_size > m_cmac.output_length())
		throw new Invalid_Argument(name() ~ ": Bad tag size " ~ std.conv.to!string(tag_size));
}

void EAX_Mode::clear()
{
	m_cipher.reset();
	m_ctr.reset();
	m_cmac.reset();
	zeroise(m_ad_mac);
	zeroise(m_nonce_mac);
}

string EAX_Mode::name() const
{
	return (m_cipher.name() ~ "/EAX");
}

size_t EAX_Mode::update_granularity() const
{
	return 8 * m_cipher.parallel_bytes();
}

Key_Length_Specification EAX_Mode::key_spec() const
{
	return m_cipher.key_spec();
}

/*
* Set the EAX key
*/
void EAX_Mode::key_schedule(in ubyte* key, size_t length)
{
	/*
	* These could share the key schedule, which is one nice part of EAX,
	* but it's much easier to ignore that here...
	*/
	m_ctr.set_key(key, length);
	m_cmac.set_key(key, length);

	m_ad_mac = eax_prf(1, block_size(), *m_cmac, null, 0);
}

/*
* Set the EAX associated data
*/
void EAX_Mode::set_associated_data(in ubyte* ad, size_t length)
{
	m_ad_mac = eax_prf(1, block_size(), *m_cmac, ad, length);
}

SafeVector!ubyte EAX_Mode::start(in ubyte* nonce, size_t nonce_len)
{
	if (!valid_nonce_length(nonce_len))
		throw new Invalid_IV_Length(name(), nonce_len);

	m_nonce_mac = eax_prf(0, block_size(), *m_cmac, nonce, nonce_len);

	m_ctr.set_iv(&m_nonce_mac[0], m_nonce_mac.size());

	for (size_t i = 0; i != block_size() - 1; ++i)
		m_cmac.update(0);
	m_cmac.update(2);

	return SafeVector!ubyte();
}

void EAX_Encryption::update(SafeVector!ubyte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	ubyte* buf = &buffer[offset];

	m_ctr.cipher(buf, buf, sz);
	m_cmac.update(buf, sz);
}

void EAX_Encryption::finish(SafeVector!ubyte buffer, size_t offset)
{
	update(buffer, offset);

	SafeVector!ubyte data_mac = m_cmac.flush();
	xor_buf(data_mac, m_nonce_mac, data_mac.size());
	xor_buf(data_mac, m_ad_mac, data_mac.size());

	buffer += Pair(&data_mac[0], tag_size());
}

void EAX_Decryption::update(SafeVector!ubyte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	ubyte* buf = &buffer[offset];

	m_cmac.update(buf, sz);
	m_ctr.cipher(buf, buf, sz);
}

void EAX_Decryption::finish(SafeVector!ubyte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	ubyte* buf = &buffer[offset];

	BOTAN_ASSERT(sz >= tag_size(), "Have the tag as part of final input");

	const size_t remaining = sz - tag_size();

	if (remaining)
	{
		m_cmac.update(buf, remaining);
		m_ctr.cipher(buf, buf, remaining);
	}

	const ubyte* included_tag = &buf[remaining];

	SafeVector!ubyte mac = m_cmac.flush();
	mac ^= m_nonce_mac;
	mac ^= m_ad_mac;

	if (!same_mem(&mac[0], included_tag, tag_size()))
		throw new Integrity_Failure("EAX tag check failed");

	buffer.resize(offset + remaining);
}

}
