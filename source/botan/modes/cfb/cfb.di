/*
* CFB mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_MODE_CFB_H__

#include <botan/cipher_mode.h>
#include <botan/block_cipher.h>
#include <botan/mode_pad.h>
/**
* CFB Mode
*/
class CFB_Mode : public Cipher_Mode
{
	public:
		SafeArray!byte start(const byte nonce[], size_t nonce_len) override;

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

		SafeArray!byte& shift_register() { return m_shift_register; }

		SafeArray!byte& keystream_buf() { return m_keystream_buf; }

	private:
		void key_schedule(const byte key[], size_t length) override;

		std::unique_ptr<BlockCipher> m_cipher;
		SafeArray!byte m_shift_register;
		SafeArray!byte m_keystream_buf;
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

		void update(SafeArray!byte& blocks, size_t offset = 0) override;

		void finish(SafeArray!byte& final_block, size_t offset = 0) override;
};

/**
* CFB Decryption
*/
class CFB_Decryption : public CFB_Mode
{
	public:
		CFB_Decryption(BlockCipher* cipher, size_t feedback_bits) :
			CFB_Mode(cipher, feedback_bits) {}

		void update(SafeArray!byte& blocks, size_t offset = 0) override;

		void finish(SafeArray!byte& final_block, size_t offset = 0) override;
};