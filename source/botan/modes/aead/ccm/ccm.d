/*
* CCM Mode Encryption
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.ccm;
import botan.parsing;
import botan.internal.xor_buf;
import algorithm;
/*
* CCM_Mode Constructor
*/
CCM_Mode::CCM_Mode(BlockCipher* cipher, size_t tag_size, size_t L) :
	m_tag_size(tag_size),
	m_L(L),
	m_cipher(cipher)
{
	if (m_cipher->block_size() != BS)
		throw new std::invalid_argument(m_cipher->name() + " cannot be used with CCM mode");

	if (L < 2 || L > 8)
		throw new std::invalid_argument("Invalid CCM L value " + std::to_string(L));

	if (tag_size < 4 || tag_size > 16 || tag_size % 2 != 0)
		throw new std::invalid_argument("invalid CCM tag length " + std::to_string(tag_size));
}

void CCM_Mode::clear()
{
	m_cipher.reset();
	m_msg_buf.clear();
	m_ad_buf.clear();
}

string CCM_Mode::name() const
{
	return (m_cipher->name() + "/CCM(" + std::to_string(tag_size()) + "," + std::to_string(L())) + ")";
}

bool CCM_Mode::valid_nonce_length(size_t n) const
{
	return (n == (15-L()));
}

size_t CCM_Mode::default_nonce_length() const
{
	return (15-L());
}

size_t CCM_Mode::update_granularity() const
{
	/*
	This value does not particularly matter as regardless CCM_Mode::update
	buffers all input, so in theory this could be 1. However as for instance
	Transformation_Filter creates update_granularity() byte buffers, use a
	somewhat large size to avoid bouncing on a tiny buffer.
	*/
	return m_cipher->parallel_bytes();
}

Key_Length_Specification CCM_Mode::key_spec() const
{
	return m_cipher->key_spec();
}

void CCM_Mode::key_schedule(in byte* key, size_t length)
{
	m_cipher->set_key(key, length);
}

void CCM_Mode::set_associated_data(in byte* ad, size_t length)
{
	m_ad_buf.clear();

	if (length)
	{
		// FIXME: support larger AD using length encoding rules
		BOTAN_ASSERT(length < (0xFFFF - 0xFF), "Supported CCM AD length");

		m_ad_buf.push_back(get_byte<ushort>(0, length));
		m_ad_buf.push_back(get_byte<ushort>(1, length));
		m_ad_buf += Pair(ad, length);
		while(m_ad_buf.size() % BS)
			m_ad_buf.push_back(0); // pad with zeros to full block size
	}
}

SafeVector!byte CCM_Mode::start(in byte* nonce, size_t nonce_len)
{
	if (!valid_nonce_length(nonce_len))
		throw new Invalid_IV_Length(name(), nonce_len);

	m_nonce.assign(nonce, nonce + nonce_len);
	m_msg_buf.clear();

	return SafeVector!byte();
}

void CCM_Mode::update(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
	buffer.resize(offset); // truncate msg
}

void CCM_Mode::encode_length(size_t len, byte* output)
{
	const size_t len_bytes = L();

	BOTAN_ASSERT(len_bytes < sizeof(size_t), "Length field fits");

	for (size_t i = 0; i != len_bytes; ++i)
		output[len_bytes-1-i] = get_byte(sizeof(size_t)-1-i, len);

	BOTAN_ASSERT((len >> (len_bytes*8)) == 0, "Message length fits in field");
}

void CCM_Mode::inc(SafeVector!byte C)
{
	for (size_t i = 0; i != C.size(); ++i)
		if (++C[C.size()-i-1])
			break;
}

SafeVector!byte CCM_Mode::format_b0(size_t sz)
{
	SafeVector!byte B0(BS);

	const byte b_flags = (m_ad_buf.size() ? 64 : 0) + (((tag_size()/2)-1) << 3) + (L()-1);

	B0[0] = b_flags;
	copy_mem(&B0[1], &m_nonce[0], m_nonce.size());
	encode_length(sz, &B0[m_nonce.size()+1]);

	return B0;
}

SafeVector!byte CCM_Mode::format_c0()
{
	SafeVector!byte C(BS);

	const byte a_flags = L()-1;

	C[0] = a_flags;
	copy_mem(&C[1], &m_nonce[0], m_nonce.size());

	return C;
}

void CCM_Encryption::finish(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");

	buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	in SafeVector!byte ad = ad_buf();
	BOTAN_ASSERT(ad.size() % BS == 0, "AD is block size multiple");

	const BlockCipher& E = cipher();

	SafeVector!byte T(BS);
	E.encrypt(format_b0(sz), T);

	for (size_t i = 0; i != ad.size(); i += BS)
	{
		xor_buf(&T[0], &ad[i], BS);
		E.encrypt(T);
	}

	SafeVector!byte C = format_c0();
	SafeVector!byte S0(BS);
	E.encrypt(C, S0);
	inc(C);

	SafeVector!byte X(BS);

	const byte* buf_end = &buf[sz];

	while(buf != buf_end)
	{
		const size_t to_proc = std::min<size_t>(BS, buf_end - buf);

		xor_buf(&T[0], buf, to_proc);
		E.encrypt(T);

		E.encrypt(C, X);
		xor_buf(buf, &X[0], to_proc);
		inc(C);

		buf += to_proc;
	}

	T ^= S0;

	buffer += Pair(&T[0], tag_size());
}

void CCM_Decryption::finish(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");

	buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());

	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	BOTAN_ASSERT(sz >= tag_size(), "We have the tag");

	in SafeVector!byte ad = ad_buf();
	BOTAN_ASSERT(ad.size() % BS == 0, "AD is block size multiple");

	const BlockCipher& E = cipher();

	SafeVector!byte T(BS);
	E.encrypt(format_b0(sz - tag_size()), T);

	for (size_t i = 0; i != ad.size(); i += BS)
	{
		xor_buf(&T[0], &ad[i], BS);
		E.encrypt(T);
	}

	SafeVector!byte C = format_c0();

	SafeVector!byte S0(BS);
	E.encrypt(C, S0);
	inc(C);

	SafeVector!byte X(BS);

	const byte* buf_end = &buf[sz - tag_size()];

	while(buf != buf_end)
	{
		const size_t to_proc = std::min<size_t>(BS, buf_end - buf);

		E.encrypt(C, X);
		xor_buf(buf, &X[0], to_proc);
		inc(C);

		xor_buf(&T[0], buf, to_proc);
		E.encrypt(T);

		buf += to_proc;
	}

	T ^= S0;

	if (!same_mem(&T[0], buf_end, tag_size()))
		throw new Integrity_Failure("CCM tag check failed");

	buffer.resize(buffer.size() - tag_size());
}

}
