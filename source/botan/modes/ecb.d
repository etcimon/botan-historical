/*
* ECB Mode
* (C) 1999-2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.ecb;

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.rounding;

/**
* ECB mode
*/
class ECB_Mode : Cipher_Mode
{
public:
	override SafeVector!ubyte start(const ubyte[], size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name(), nonce_len);
		
		return SafeVector!ubyte();
	}

	override string name() const
	{
		return cipher().name() ~ "/ECB/" ~ padding().name();
	}

	override size_t update_granularity() const
	{
		return cipher().parallel_bytes();
	}

	override Key_Length_Specification key_spec() const
	{
		return cipher().key_spec();
	}

	override size_t default_nonce_length() const
	{
		return 0;
	}

	override bool valid_nonce_length(size_t n) const
	{
		return (n == 0);
	}

	override void clear()
	{
		m_cipher.clear();
	}
package:
	this(BlockCipher cipher, BlockCipherModePaddingMethod padding)
	{
		m_cipher = cipher;
		m_padding = padding;
		if (!m_padding.valid_blocksize(cipher.block_size()))
			throw new Invalid_Argument("Padding " ~ m_padding.name() +
			                           " cannot be used with " ~
			                           cipher.name() ~ "/ECB");
	}

	const BlockCipher cipher() const { return *m_cipher; }

	const BlockCipherModePaddingMethod& padding() const { return *m_padding; }

private:
	override void key_schedule(in ubyte* key, size_t length)
	{
		m_cipher.set_key(key, length);
	}

	Unique!BlockCipher m_cipher;
	Unique!BlockCipherModePaddingMethod m_padding;
};

/**
* ECB Encryption
*/
class ECB_Encryption : ECB_Mode
{
public:
	this(BlockCipher cipher, BlockCipherModePaddingMethod padding) 
	{
		super(cipher, padding);
	}

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size();
		
		BOTAN_ASSERT(sz % BS == 0, "ECB input is full blocks");
		const size_t blocks = sz / BS;
		
		cipher().encrypt_n(&buf[0], &buf[0], blocks);
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		
		const size_t BS = cipher().block_size();
		
		const size_t bytes_in_final_block = sz % BS;
		
		padding().add_padding(buffer, bytes_in_final_block, BS);
		
		if (buffer.length % BS)
			throw new Exception("Did not pad to full block size in " ~ name());
		
		update(buffer, offset);
	}

	override size_t output_length(size_t input_length) const
	{
		return round_up(input_length, cipher().block_size());
	}

	override size_t minimum_final_size() const
	{
		return 0;
	}
};

/**
* ECB Decryption
*/
class ECB_Decryption : ECB_Mode
{
public:
	this(BlockCipher cipher, BlockCipherModePaddingMethod padding)
	{
		super(cipher, padding);
	}

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size();
		
		BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
		size_t blocks = sz / BS;
		
		cipher().decrypt_n(&buf[0], &buf[0], blocks);
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		
		const size_t BS = cipher().block_size();
		
		if (sz == 0 || sz % BS)
			throw new Decoding_Error(name() ~ ": Ciphertext not a multiple of block size");
		
		update(buffer, offset);
		
		const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.length-BS], BS);
		buffer.resize(buffer.length - pad_bytes); // remove padding
	}

	override size_t output_length(size_t input_length) const
	{
		return input_length;
	}

	override size_t minimum_final_size() const
	{
		return cipher().block_size();
	}
};