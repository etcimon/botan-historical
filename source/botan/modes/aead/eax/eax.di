/*
* EAX Mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
/**
* EAX base class
*/
class EAX_Mode : public AEAD_Mode
{
	public:
		SafeVector!byte start(in byte* nonce, size_t nonce_len) override;

		void set_associated_data(in byte* ad, size_t ad_len) override;

		string name() const override;

		size_t update_granularity() const override;

		Key_Length_Specification key_spec() const override;

		// EAX supports arbitrary nonce lengths
		bool valid_nonce_length(size_t) const override { return true; }

		size_t tag_size() const override { return m_tag_size; }

		void clear() override;
	protected:
		void key_schedule(in byte* key, size_t length) override;

		/**
		* @param cipher the cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		EAX_Mode(BlockCipher* cipher, size_t tag_size);

		size_t block_size() const { return m_cipher->block_size(); }

		size_t m_tag_size;

		std::unique_ptr<BlockCipher> m_cipher;
		std::unique_ptr<StreamCipher> m_ctr;
		std::unique_ptr<MessageAuthenticationCode> m_cmac;

		SafeVector!byte m_ad_mac;

		SafeVector!byte m_nonce_mac;
};

/**
* EAX Encryption
*/
class EAX_Encryption : public EAX_Mode
{
	public:
		/**
		* @param cipher a 128-bit block cipher
		* @param tag_size is how big the auth tag will be
		*/
		EAX_Encryption(BlockCipher* cipher, size_t tag_size = 0) :
			EAX_Mode(cipher, tag_size) {}

		size_t output_length(size_t input_length) const override
		{ return input_length + tag_size(); }

		size_t minimum_final_size() const override { return 0; }

		void update(SafeVector!byte blocks, size_t offset = 0) override;

		void finish(SafeVector!byte final_block, size_t offset = 0) override;
};

/**
* EAX Decryption
*/
class EAX_Decryption : public EAX_Mode
{
	public:
		/**
		* @param cipher a 128-bit block cipher
		* @param tag_size is how big the auth tag will be
		*/
		EAX_Decryption(BlockCipher* cipher, size_t tag_size = 0) :
			EAX_Mode(cipher, tag_size) {}

		size_t output_length(size_t input_length) const override
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		size_t minimum_final_size() const override { return tag_size(); }

		void update(SafeVector!byte blocks, size_t offset = 0) override;

		void finish(SafeVector!byte final_block, size_t offset = 0) override;
};