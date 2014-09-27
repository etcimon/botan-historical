/*
* CFB mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.cipher_mode;
import botan.block_cipher;
import botan.mode_pad;
/**
* CFB Mode
*/
class CFB_Mode : public Cipher_Mode
{
	public:
		SafeVector!byte start(in byte* nonce, size_t nonce_len) override;

		string name() const override;

		size_t update_granularity() const override;

		size_t minimum_final_size() const override;

		Key_Length_Specification key_spec() const override;

		size_t output_length(size_t input_length) const override;

		size_t default_nonce_length() const override;

		bool valid_nonce_length(size_t n) const override;

		void clear() override;
	protected:
		CFB_Mode(BlockCipher* cipher, size_t feedback_bits);

		const BlockCipher& cipher() const { return *m_cipher; }

		size_t feedback() const { return m_feedback_bytes; }

		SafeVector!byte shift_register() { return m_shift_register; }

		SafeVector!byte keystream_buf() { return m_keystream_buf; }

	private:
		void key_schedule(in byte* key, size_t length) override;

		Unique!BlockCipher m_cipher;
		SafeVector!byte m_shift_register;
		SafeVector!byte m_keystream_buf;
		size_t m_feedback_bytes;
};

/**
* CFB Encryption
*/
class CFB_Encryption : public CFB_Mode
{
	public:
		CFB_Encryption(BlockCipher* cipher, size_t feedback_bits) :
			CFB_Mode(cipher, feedback_bits) {}

		void update(SafeVector!byte blocks, size_t offset = 0) override;

		void finish(SafeVector!byte final_block, size_t offset = 0) override;
};

/**
* CFB Decryption
*/
class CFB_Decryption : public CFB_Mode
{
	public:
		CFB_Decryption(BlockCipher* cipher, size_t feedback_bits) :
			CFB_Mode(cipher, feedback_bits) {}

		void update(SafeVector!byte blocks, size_t offset = 0) override;

		void finish(SafeVector!byte final_block, size_t offset = 0) override;
};