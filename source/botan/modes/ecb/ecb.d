/*
* ECB Mode
* (C) 1999-2009,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.ecb;
import botan.loadstor;
import botan.internal.xor_buf;
import botan.internal.rounding;
ECB_Mode::ECB_Mode(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
	m_cipher(cipher),
	m_padding(padding)
{
	if (!m_padding->valid_blocksize(cipher->block_size()))
		throw new std::invalid_argument("Padding " + m_padding->name() +
											 " cannot be used with " +
											 cipher->name() + "/ECB");
}

void ECB_Mode::clear()
{
	m_cipher->clear();
}

string ECB_Mode::name() const
{
	return cipher().name() + "/ECB/" + padding().name();
}

size_t ECB_Mode::update_granularity() const
{
	return cipher().parallel_bytes();
}

Key_Length_Specification ECB_Mode::key_spec() const
{
	return cipher().key_spec();
}

size_t ECB_Mode::default_nonce_length() const
{
	return 0;
}

bool ECB_Mode::valid_nonce_length(size_t n) const
{
	return (n == 0);
}

void ECB_Mode::key_schedule(in byte* key, size_t length)
{
	m_cipher->set_key(key, length);
}

SafeVector!byte ECB_Mode::start(const byte[], size_t nonce_len)
{
	if (!valid_nonce_length(nonce_len))
		throw new Invalid_IV_Length(name(), nonce_len);

	return SafeVector!byte();
}

size_t ECB_Encryption::minimum_final_size() const
{
	return 0;
}

size_t ECB_Encryption::output_length(size_t input_length) const
{
	return round_up(input_length, cipher().block_size());
}

void ECB_Encryption::update(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	const size_t BS = cipher().block_size();

	BOTAN_ASSERT(sz % BS == 0, "ECB input is full blocks");
	const size_t blocks = sz / BS;

	cipher().encrypt_n(&buf[0], &buf[0], blocks);
}

void ECB_Encryption::finish(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;

	const size_t BS = cipher().block_size();

	const size_t bytes_in_final_block = sz % BS;

	padding().add_padding(buffer, bytes_in_final_block, BS);

	if (buffer.size() % BS)
		throw new Exception("Did not pad to full block size in " + name());

	update(buffer, offset);
}

size_t ECB_Decryption::output_length(size_t input_length) const
{
	return input_length;
}

size_t ECB_Decryption::minimum_final_size() const
{
	return cipher().block_size();
}

void ECB_Decryption::update(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	const size_t BS = cipher().block_size();

	BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
	size_t blocks = sz / BS;

	cipher().decrypt_n(&buf[0], &buf[0], blocks);
}

void ECB_Decryption::finish(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;

	const size_t BS = cipher().block_size();

	if (sz == 0 || sz % BS)
		throw new Decoding_Error(name() + ": Ciphertext not a multiple of block size");

	update(buffer, offset);

	const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.size()-BS], BS);
	buffer.resize(buffer.size() - pad_bytes); // remove padding
}

}
