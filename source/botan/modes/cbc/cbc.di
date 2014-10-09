/*
* CBC mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.cipher_mode;
import botan.block.block_cipher;
import botan.mode_pad;
/**
* CBC Mode
*/
class CBC_Mode : Cipher_Mode
{
	public:
		override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len);

		override string name() const;

		override size_t update_granularity() const;

		override Key_Length_Specification key_spec() const;

		override size_t default_nonce_length() const;

		override bool valid_nonce_length(size_t n) const;

		override void clear();
	package:
		CBC_Mode(BlockCipher cipher, BlockCipherModePaddingMethod* padding);

		const BlockCipher& cipher() const { return *m_cipher; }

		const BlockCipherModePaddingMethod& padding() const
		{
			BOTAN_ASSERT_NONNULL(m_padding);
			return *m_padding;
		}

		SafeVector!ubyte state() { return m_state; }

		ubyte* state_ptr() { return &m_state[0]; }

	private:
		override void key_schedule(in ubyte* key, size_t length);

		Unique!BlockCipher m_cipher;
		Unique!BlockCipherModePaddingMethod m_padding;
		SafeVector!ubyte m_state;
};

/**
* CBC Encryption
*/
class CBC_Encryption : CBC_Mode
{
	public:
		CBC_Encryption(BlockCipher cipher, BlockCipherModePaddingMethod* padding) :
			CBC_Mode(cipher, padding) {}

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t output_length(size_t input_length) const;

		override size_t minimum_final_size() const;
};

/**
* CBC Encryption with ciphertext stealing (CBC-CS3 variant)
*/
class CTS_Encryption : CBC_Encryption
{
	public:
		CTS_Encryption(BlockCipher cipher) : CBC_Encryption(cipher, null) {}

		override size_t output_length(size_t input_length) const;

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t minimum_final_size() const;

		bool valid_nonce_length(size_t n) const;
};

/**
* CBC Decryption
*/
class CBC_Decryption : CBC_Mode
{
	public:
		CBC_Decryption(BlockCipher cipher, BlockCipherModePaddingMethod* padding) :
			CBC_Mode(cipher, padding), m_tempbuf(update_granularity()) {}

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t output_length(size_t input_length) const;

		override size_t minimum_final_size() const;
	private:
		SafeVector!ubyte m_tempbuf;
};

/**
* CBC Decryption with ciphertext stealing (CBC-CS3 variant)
*/
class CTS_Decryption : CBC_Decryption
{
	public:
		CTS_Decryption(BlockCipher cipher) : CBC_Decryption(cipher, null) {}

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t minimum_final_size() const;

		bool valid_nonce_length(size_t n) const;
};