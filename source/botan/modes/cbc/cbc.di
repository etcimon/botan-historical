/*
* CBC mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_MODE_CBC_H__

#include <botan/cipher_mode.h>
#include <botan/block_cipher.h>
#include <botan/mode_pad.h>
/**
* CBC Mode
*/
class CBC_Mode : public Cipher_Mode
{
	public:
		SafeArray!byte start(const byte nonce[], size_t nonce_len) override;

		string name() const override;

		size_t update_granularity() const override;

		Key_Length_Specification key_spec() const override;

		size_t default_nonce_length() const override;

		bool valid_nonce_length(size_t n) const override;

		void clear() override;
	protected:
		CBC_Mode(BlockCipher* cipher, BlockCipherModePaddingMethod* padding);

		const BlockCipher& cipher() const { return *m_cipher; }

		const BlockCipherModePaddingMethod& padding() const
		{
			BOTAN_ASSERT_NONNULL(m_padding);
			return *m_padding;
		}

		SafeArray!byte& state() { return m_state; }

		byte* state_ptr() { return &m_state[0]; }

	private:
		void key_schedule(const byte key[], size_t length) override;

		std::unique_ptr<BlockCipher> m_cipher;
		std::unique_ptr<BlockCipherModePaddingMethod> m_padding;
		SafeArray!byte m_state;
};

/**
* CBC Encryption
*/
class CBC_Encryption : public CBC_Mode
{
	public:
		CBC_Encryption(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
			CBC_Mode(cipher, padding) {}

		void update(SafeArray!byte& blocks, size_t offset = 0) override;

		void finish(SafeArray!byte& final_block, size_t offset = 0) override;

		size_t output_length(size_t input_length) const override;

		size_t minimum_final_size() const override;
};

/**
* CBC Encryption with ciphertext stealing (CBC-CS3 variant)
*/
class CTS_Encryption : public CBC_Encryption
{
	public:
		CTS_Encryption(BlockCipher* cipher) : CBC_Encryption(cipher, nullptr) {}

		size_t output_length(size_t input_length) const override;

		void finish(SafeArray!byte& final_block, size_t offset = 0) override;

		size_t minimum_final_size() const override;

		bool valid_nonce_length(size_t n) const;
};

/**
* CBC Decryption
*/
class CBC_Decryption : public CBC_Mode
{
	public:
		CBC_Decryption(BlockCipher* cipher, BlockCipherModePaddingMethod* padding) :
			CBC_Mode(cipher, padding), m_tempbuf(update_granularity()) {}

		void update(SafeArray!byte& blocks, size_t offset = 0) override;

		void finish(SafeArray!byte& final_block, size_t offset = 0) override;

		size_t output_length(size_t input_length) const override;

		size_t minimum_final_size() const override;
	private:
		SafeArray!byte m_tempbuf;
};

/**
* CBC Decryption with ciphertext stealing (CBC-CS3 variant)
*/
class CTS_Decryption : public CBC_Decryption
{
	public:
		CTS_Decryption(BlockCipher* cipher) : CBC_Decryption(cipher, nullptr) {}

		void finish(SafeArray!byte& final_block, size_t offset = 0) override;

		size_t minimum_final_size() const override;

		bool valid_nonce_length(size_t n) const;
};