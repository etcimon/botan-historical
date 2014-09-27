/*
* GCM Mode Encryption
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.gcm;
import botan.ctr;
import botan.internal.xor_buf;
import botan.loadstor;

#if defined(BOTAN_HAS_GCM_CLMUL)
  import botan.internal.clmul;
  import botan.cpuid;
#endif
void GHASH::gcm_multiply(SafeVector!byte x) const
{
#if defined(BOTAN_HAS_GCM_CLMUL)
	if (CPUID::has_clmul())
		return gcm_multiply_clmul(&x[0], &m_H[0]);
#endif

	static const ulong R = 0xE100000000000000;

	ulong[2] H = {
		load_be!ulong(&m_H[0], 0),
		load_be!ulong(&m_H[0], 1)
};

	ulong[2] Z = { 0, 0 };

	// SSE2 might be useful here

	for (size_t i = 0; i != 2; ++i)
	{
		const ulong X = load_be!ulong(&x[0], i);

		for (size_t j = 0; j != 64; ++j)
		{
			if ((X >> (63-j)) & 1)
			{
				Z[0] ^= H[0];
				Z[1] ^= H[1];
			}

			const ulong r = (H[1] & 1) ? R : 0;

			H[1] = (H[0] << 63) | (H[1] >> 1);
			H[0] = (H[0] >> 1) ^ r;
		}
	}

	store_be!ulong(&x[0], Z[0], Z[1]);
}

void GHASH::ghash_update(SafeVector!byte ghash,
								 in byte* input, size_t length)
{
	const size_t BS = 16;

	/*
	This assumes if less than block size input then we're just on the
	final block and should pad with zeros
	*/
	while(length)
	{
		const size_t to_proc = std::min(length, BS);

		xor_buf(&ghash[0], &input[0], to_proc);

		gcm_multiply(ghash);

		input += to_proc;
		length -= to_proc;
	}
}

void GHASH::key_schedule(in byte* key, size_t length)
{
	m_H.assign(key, key+length);
	m_H_ad.resize(16);
	m_ad_len = 0;
	m_text_len = 0;
}

void GHASH::start(in byte* nonce, size_t len)
{
	m_nonce.assign(nonce, nonce + len);
	m_ghash = m_H_ad;
}

void GHASH::set_associated_data(in byte* input, size_t length)
{
	zeroise(m_H_ad);

	ghash_update(m_H_ad, input, length);
	m_ad_len = length;
}

void GHASH::update(in byte* input, size_t length)
{
	BOTAN_ASSERT(m_ghash.size() == 16, "Key was set");

	m_text_len += length;

	ghash_update(m_ghash, input, length);
}

void GHASH::add_final_block(SafeVector!byte hash,
									 size_t ad_len, size_t text_len)
{
	SafeVector!byte final_block(16);
	store_be!ulong(&final_block[0], 8*ad_len, 8*text_len);
	ghash_update(hash, &final_block[0], final_block.size());
}

SafeVector!byte GHASH::flush()
{
	add_final_block(m_ghash, m_ad_len, m_text_len);

	SafeVector!byte mac;
	mac.swap(m_ghash);

	mac ^= m_nonce;
	m_text_len = 0;
	return mac;
}

SafeVector!byte GHASH::nonce_hash(in byte* nonce, size_t nonce_len)
{
	BOTAN_ASSERT(m_ghash.size() == 0, "nonce_hash called during wrong time");
	SafeVector!byte y0(16);

	ghash_update(y0, nonce, nonce_len);
	add_final_block(y0, 0, nonce_len);

	return y0;
}

void GHASH::clear()
{
	zeroise(m_H);
	zeroise(m_H_ad);
	m_ghash.clear();
	m_text_len = m_ad_len = 0;
}

/*
* GCM_Mode Constructor
*/
GCM_Mode::GCM_Mode(BlockCipher* cipher, size_t tag_size) :
	m_tag_size(tag_size),
	m_cipher_name(cipher->name())
{
	if (cipher->block_size() != BS)
		throw new std::invalid_argument("GCM requires a 128 bit cipher so cannot be used with " +
											 cipher->name());

	m_ghash.reset(new GHASH);

	m_ctr.reset(new CTR_BE(cipher)); // CTR_BE takes ownership of cipher

	if (m_tag_size != 8 && m_tag_size != 16)
		throw new Invalid_Argument(name() + ": Bad tag size " + std::to_string(m_tag_size));
}

void GCM_Mode::clear()
{
	m_ctr->clear();
	m_ghash->clear();
}

string GCM_Mode::name() const
{
	return (m_cipher_name + "/GCM");
}

size_t GCM_Mode::update_granularity() const
{
	return 4096; // CTR-BE's internal block size
}

Key_Length_Specification GCM_Mode::key_spec() const
{
	return m_ctr->key_spec();
}

void GCM_Mode::key_schedule(in byte* key, size_t length)
{
	m_ctr->set_key(key, keylen);

	const Vector!( byte ) zeros(BS);
	m_ctr->set_iv(&zeros[0], zeros.size());

	SafeVector!byte H(BS);
	m_ctr->encipher(H);
	m_ghash->set_key(H);
}

void GCM_Mode::set_associated_data(in byte* ad, size_t ad_len)
{
	m_ghash->set_associated_data(ad, ad_len);
}

SafeVector!byte GCM_Mode::start(in byte* nonce, size_t nonce_len)
{
	if (!valid_nonce_length(nonce_len))
		throw new Invalid_IV_Length(name(), nonce_len);

	SafeVector!byte y0(BS);

	if (nonce_len == 12)
	{
		copy_mem(&y0[0], nonce, nonce_len);
		y0[15] = 1;
	}
	else
	{
		y0 = m_ghash->nonce_hash(nonce, nonce_len);
	}

	m_ctr->set_iv(&y0[0], y0.size());

	SafeVector!byte m_enc_y0(BS);
	m_ctr->encipher(m_enc_y0);

	m_ghash->start(&m_enc_y0[0], m_enc_y0.size());

	return SafeVector!byte();
}

void GCM_Encryption::update(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	m_ctr->cipher(buf, buf, sz);
	m_ghash->update(buf, sz);
}

void GCM_Encryption::finish(SafeVector!byte buffer, size_t offset)
{
	update(buffer, offset);
	auto mac = m_ghash->flush();
	buffer += Pair(&mac[0], tag_size());
}

void GCM_Decryption::update(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	m_ghash->update(buf, sz);
	m_ctr->cipher(buf, buf, sz);
}

void GCM_Decryption::finish(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	BOTAN_ASSERT(sz >= tag_size(), "Have the tag as part of final input");

	const size_t remaining = sz - tag_size();

	// handle any final input before the tag
	if (remaining)
	{
		m_ghash->update(buf, remaining);
		m_ctr->cipher(buf, buf, remaining);
	}

	auto mac = m_ghash->flush();

	const byte* included_tag = &buffer[remaining];

	if (!same_mem(&mac[0], included_tag, tag_size()))
		throw new Integrity_Failure("GCM tag check failed");

	buffer.resize(offset + remaining);
}

}
