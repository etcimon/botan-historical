/*
* XTS mode, from IEEE P1619
* (C) 2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.cipher_mode;
import botan.block_cipher;
/**
* IEEE P1619 XTS Mode
*/
class XTS_Mode : Cipher_Mode
{
	public:
		override string name() const;

		override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len);

		override size_t update_granularity() const;

		override size_t minimum_final_size() const;

		override Key_Length_Specification key_spec() const;

		override size_t default_nonce_length() const;

		override bool valid_nonce_length(size_t n) const;

		override void clear();
	package:
		XTS_Mode(BlockCipher cipher);

		const ubyte* tweak() const { return &m_tweak[0]; }

		const BlockCipher& cipher() const { return *m_cipher; }

		void update_tweak(size_t last_used);

	private:
		override void key_schedule(in ubyte* key, size_t length);

		Unique!BlockCipher m_cipher, m_tweak_cipher;
		SafeVector!ubyte m_tweak;
};

/**
* IEEE P1619 XTS Encryption
*/
class XTS_Encryption : XTS_Mode
{
	public:
		XTS_Encryption(BlockCipher cipher) : XTS_Mode(cipher) {}

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t output_length(size_t input_length) const;
};

/**
* IEEE P1619 XTS Decryption
*/
class XTS_Decryption : XTS_Mode
{
	public:
		XTS_Decryption(BlockCipher cipher) : XTS_Mode(cipher) {}

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t output_length(size_t input_length) const;
};