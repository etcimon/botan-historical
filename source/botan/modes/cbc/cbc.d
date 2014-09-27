/*
* CBC Mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cbc.h>
#include <botan/loadstor.h>
#include <botan/internal/xor_buf.h>
#include <botan/internal/rounding.h>
CBC_Mode::CBC_Mode(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
	m_cipher(cipher),
	m_padding(padding),
	m_state(m_cipher->block_size())
{
	if (m_padding && !m_padding->valid_blocksize(cipher->block_size()))
		throw new std::invalid_argument("Padding " + m_padding->name() +
											 " cannot be used with " +
											 cipher->name() + "/CBC");
}

void CBC_Mode::clear()
{
	m_cipher->clear();
	m_state.clear();
}

string CBC_Mode::name() const
{
	if (m_padding)
		return cipher().name() + "/CBC/" + padding().name();
	else
		return cipher().name() + "/CBC/CTS";
}

size_t CBC_Mode::update_granularity() const
{
	return cipher().parallel_bytes();
}

Key_Length_Specification CBC_Mode::key_spec() const
{
	return cipher().key_spec();
}

size_t CBC_Mode::default_nonce_length() const
{
	return cipher().block_size();
}

bool CBC_Mode::valid_nonce_length(size_t n) const
{
	return (n == 0 || n == cipher().block_size());
}

void CBC_Mode::key_schedule(in byte* key, size_t length)
{
	m_cipher->set_key(key, length);
}

SafeVector!byte CBC_Mode::start(in byte* nonce, size_t nonce_len)
{
	if (!valid_nonce_length(nonce_len))
		throw new Invalid_IV_Length(name(), nonce_len);

	/*
	* A nonce of zero length means carry the last ciphertext value over
	* as the new IV, as unfortunately some protocols require this. If
	* this is the first message then we use an IV of all zeros.
	*/
	if (nonce_len)
		m_state.assign(nonce, nonce + nonce_len);

	return SafeVector!byte();
}

size_t CBC_Encryption::minimum_final_size() const
{
	return 0;
}

size_t CBC_Encryption::output_length(size_t input_length) const
{
	return round_up(input_length, cipher().block_size());
}

void CBC_Encryption::update(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	const size_t BS = cipher().block_size();

	BOTAN_ASSERT(sz % BS == 0, "CBC input is full blocks");
	const size_t blocks = sz / BS;

	const byte* prev_block = state_ptr();

	if (blocks)
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			xor_buf(&buf[BS*i], prev_block, BS);
			cipher().encrypt(&buf[BS*i]);
			prev_block = &buf[BS*i];
		}

		state().assign(&buf[BS*(blocks-1)], &buf[BS*blocks]);
	}
}

void CBC_Encryption::finish(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");

	const size_t BS = cipher().block_size();

	const size_t bytes_in_final_block = (buffer.size()-offset) % BS;

	padding().add_padding(buffer, bytes_in_final_block, BS);

	if ((buffer.size()-offset) % BS)
		throw new Exception("Did not pad to full block size in " + name());

	update(buffer, offset);
}

bool CTS_Encryption::valid_nonce_length(size_t n) const
{
	return (n == cipher().block_size());
}

size_t CTS_Encryption::minimum_final_size() const
{
	return cipher().block_size() + 1;
}

size_t CTS_Encryption::output_length(size_t input_length) const
{
	return input_length; // no ciphertext expansion in CTS
}

void CTS_Encryption::finish(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	byte* buf = &buffer[offset];
	const size_t sz = buffer.size() - offset;

	const size_t BS = cipher().block_size();

	if (sz < BS + 1)
		throw new Encoding_Error(name() + ": insufficient data to encrypt");

	if (sz % BS == 0)
	{
		update(buffer, offset);

		// swap last two blocks
		for (size_t i = 0; i != BS; ++i)
			std::swap(buffer[buffer.size()-BS+i], buffer[buffer.size()-2*BS+i]);
	}
	else
	{
		const size_t full_blocks = ((sz / BS) - 1) * BS;
		const size_t final_bytes = sz - full_blocks;
		BOTAN_ASSERT(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");

		SafeVector!byte last(buf + full_blocks, buf + full_blocks + final_bytes);
		buffer.resize(full_blocks + offset);
		update(buffer, offset);

		xor_buf(&last[0], state_ptr(), BS);
		cipher().encrypt(&last[0]);

		for (size_t i = 0; i != final_bytes - BS; ++i)
		{
			last[i] ^= last[i + BS];
			last[i + BS] ^= last[i];
		}

		cipher().encrypt(&last[0]);

		buffer += last;
	}
}

size_t CBC_Decryption::output_length(size_t input_length) const
{
	return input_length; // precise for CTS, worst case otherwise
}

size_t CBC_Decryption::minimum_final_size() const
{
	return cipher().block_size();
}

void CBC_Decryption::update(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	const size_t BS = cipher().block_size();

	BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
	size_t blocks = sz / BS;

	while(blocks)
	{
		const size_t to_proc = std::min(BS * blocks, m_tempbuf.size());

		cipher().decrypt_n(buf, &m_tempbuf[0], to_proc / BS);

		xor_buf(&m_tempbuf[0], state_ptr(), BS);
		xor_buf(&m_tempbuf[BS], buf, to_proc - BS);
		copy_mem(state_ptr(), buf + (to_proc - BS), BS);

		copy_mem(buf, &m_tempbuf[0], to_proc);

		buf += to_proc;
		blocks -= to_proc / BS;
	}
}

void CBC_Decryption::finish(SafeVector!byte buffer, size_t offset)
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

bool CTS_Decryption::valid_nonce_length(size_t n) const
{
	return (n == cipher().block_size());
}

size_t CTS_Decryption::minimum_final_size() const
{
	return cipher().block_size() + 1;
}

void CTS_Decryption::finish(SafeVector!byte buffer, size_t offset)
{
	BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
	const size_t sz = buffer.size() - offset;
	byte* buf = &buffer[offset];

	const size_t BS = cipher().block_size();

	if (sz < BS + 1)
		throw new Encoding_Error(name() + ": insufficient data to decrypt");

	if (sz % BS == 0)
	{
		// swap last two blocks

		for (size_t i = 0; i != BS; ++i)
			std::swap(buffer[buffer.size()-BS+i], buffer[buffer.size()-2*BS+i]);

		update(buffer, offset);
	}
	else
	{
		const size_t full_blocks = ((sz / BS) - 1) * BS;
		const size_t final_bytes = sz - full_blocks;
		BOTAN_ASSERT(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");

		SafeVector!byte last(buf + full_blocks, buf + full_blocks + final_bytes);
		buffer.resize(full_blocks + offset);
		update(buffer, offset);

		cipher().decrypt(&last[0]);

		xor_buf(&last[0], &last[BS], final_bytes - BS);

		for (size_t i = 0; i != final_bytes - BS; ++i)
			std::swap(last[i], last[i + BS]);

		cipher().decrypt(&last[0]);
		xor_buf(&last[0], state_ptr(), BS);

		buffer += last;
	}
}

}
