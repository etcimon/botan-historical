/*
* SIV Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_AEAD_SIV_H__

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
/**
* Base class for SIV encryption and decryption (@see RFC 5297)
*/
class SIV_Mode : public AEAD_Mode
{
	public:
		SafeArray!byte start(const byte nonce[], size_t nonce_len) override;

		void update(SafeArray!byte& blocks, size_t offset = 0) override;

		void set_associated_data_n(size_t n, const byte ad[], size_t ad_len);

		void set_associated_data(const byte ad[], size_t ad_len) override
		{
			set_associated_data_n(0, ad, ad_len);
		}

		string name() const override;

		size_t update_granularity() const override;

		Key_Length_Specification key_spec() const override;

		bool valid_nonce_length(size_t) const override;

		void clear() override;

		size_t tag_size() const override { return 16; }

	protected:
		SIV_Mode(BlockCipher* cipher);

		StreamCipher& ctr() { return *m_ctr; }

		void set_ctr_iv(SafeArray!byte V);

		SafeArray!byte& msg_buf() { return m_msg_buf; }

		SafeArray!byte S2V(const byte text[], size_t text_len);
	private:
		MessageAuthenticationCode& cmac() { return *m_cmac; }

		void key_schedule(const byte key[], size_t length) override;

		const string m_name;

		std::unique_ptr<StreamCipher> m_ctr;
		std::unique_ptr<MessageAuthenticationCode> m_cmac;
		SafeArray!byte m_nonce, m_msg_buf;
		std::vector<SafeArray!byte> m_ad_macs;
};

/**
* SIV Encryption
*/
class SIV_Encryption : public SIV_Mode
{
	public:
		/**
		* @param cipher a block cipher
		*/
		SIV_Encryption(BlockCipher* cipher) : SIV_Mode(cipher) {}

		void finish(SafeArray!byte& final_block, size_t offset = 0) override;

		size_t output_length(size_t input_length) const override
		{ return input_length + tag_size(); }

		size_t minimum_final_size() const override { return 0; }
};

/**
* SIV Decryption
*/
class SIV_Decryption : public SIV_Mode
{
	public:
		/**
		* @param cipher a 128-bit block cipher
		*/
		SIV_Decryption(BlockCipher* cipher) : SIV_Mode(cipher) {}

		void finish(SafeArray!byte& final_block, size_t offset = 0) override;

		size_t output_length(size_t input_length) const override
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		size_t minimum_final_size() const override { return tag_size(); }
};