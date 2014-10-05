/*
* ECB Mode
* (C) 1999-2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.cipher_mode;
import botan.block_cipher;
import botan.mode_pad;
/**
* ECB mode
*/
class ECB_Mode : public Cipher_Mode
{
	public:
		SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len) override;

		string name() const override;

		size_t update_granularity() const override;

		Key_Length_Specification key_spec() const override;

		size_t default_nonce_length() const override;

		bool valid_nonce_length(size_t n) const override;

		void clear() override;
	package:
		ECB_Mode(BlockCipher cipher, BlockCipherModePaddingMethod* padding);

		const BlockCipher& cipher() const { return *m_cipher; }

		const BlockCipherModePaddingMethod& padding() const { return *m_padding; }

	private:
		void key_schedule(in ubyte* key, size_t length) override;

		Unique!BlockCipher m_cipher;
		Unique!BlockCipherModePaddingMethod m_padding;
};

/**
* ECB Encryption
*/
class ECB_Encryption : public ECB_Mode
{
	public:
		ECB_Encryption(BlockCipher cipher, BlockCipherModePaddingMethod* padding) :
			ECB_Mode(cipher, padding) {}

		void update(SafeVector!ubyte blocks, size_t offset = 0) override;

		void finish(SafeVector!ubyte final_block, size_t offset = 0) override;

		size_t output_length(size_t input_length) const override;

		size_t minimum_final_size() const override;
};

/**
* ECB Decryption
*/
class ECB_Decryption : public ECB_Mode
{
	public:
		ECB_Decryption(BlockCipher cipher, BlockCipherModePaddingMethod* padding) :
			ECB_Mode(cipher, padding) {}

		void update(SafeVector!ubyte blocks, size_t offset = 0) override;

		void finish(SafeVector!ubyte final_block, size_t offset = 0) override;

		size_t output_length(size_t input_length) const override;

		size_t minimum_final_size() const override;
};