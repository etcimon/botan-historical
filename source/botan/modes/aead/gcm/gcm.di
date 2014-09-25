/*
* GCM Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
class GHASH;

/**
* GCM Mode
*/
class GCM_Mode : public AEAD_Mode
{
	public:
		SafeArray!byte start(in byte[] nonce, size_t nonce_len) override;

		void set_associated_data(in byte[] ad, size_t ad_len) override;

		string name() const override;

		size_t update_granularity() const;

		Key_Length_Specification key_spec() const override;

		// GCM supports arbitrary nonce lengths
		bool valid_nonce_length(size_t) const override { return true; }

		size_t tag_size() const override { return m_tag_size; }

		void clear() override;
	protected:
		void key_schedule(in byte[] key) override;

		GCM_Mode(BlockCipher* cipher, size_t tag_size);

		const size_t BS = 16;

		const size_t m_tag_size;
		const string m_cipher_name;

		std::unique_ptr<StreamCipher> m_ctr;
		std::unique_ptr<GHASH> m_ghash;
};

/**
* GCM Encryption
*/
class GCM_Encryption : public GCM_Mode
{
	public:
		/**
		* @param cipher the 128 bit block cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		GCM_Encryption(BlockCipher* cipher, size_t tag_size = 16) :
			GCM_Mode(cipher, tag_size) {}

		size_t output_length(size_t input_length) const override
		{ return input_length + tag_size(); }

		size_t minimum_final_size() const override { return 0; }

		void update(SafeArray!byte blocks, size_t offset = 0) override;

		void finish(SafeArray!byte final_block, size_t offset = 0) override;
};

/**
* GCM Decryption
*/
class GCM_Decryption : public GCM_Mode
{
	public:
		/**
		* @param cipher the 128 bit block cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		GCM_Decryption(BlockCipher* cipher, size_t tag_size = 16) :
			GCM_Mode(cipher, tag_size) {}

		size_t output_length(size_t input_length) const override
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		size_t minimum_final_size() const override { return tag_size(); }

		void update(SafeArray!byte blocks, size_t offset = 0) override;

		void finish(SafeArray!byte final_block, size_t offset = 0) override;
};

/**
* GCM's GHASH
* Maybe a Transform?
*/
class GHASH : public SymmetricAlgorithm
{
	public:
		void set_associated_data(in byte[] ad, size_t ad_len);

		SafeArray!byte nonce_hash(in byte[] nonce, size_t len);

		void start(in byte[] nonce, size_t len);

		/*
		* Assumes input len is multiple of 16
		*/
		void update(in byte[] input);

		SafeArray!byte final();

		Key_Length_Specification key_spec() const { return Key_Length_Specification(16); }

		void clear() override;

		string name() const { return "GHASH"; }
	private:
		void key_schedule(in byte[] key) override;

		void gcm_multiply(SafeArray!byte x) const;

		void ghash_update(SafeArray!byte x,
								in byte[] input, size_t input_len);

		void add_final_block(SafeArray!byte x,
									size_t ad_len, size_t pt_len);

		SafeArray!byte m_H;
		SafeArray!byte m_H_ad;
		SafeArray!byte m_nonce;
		SafeArray!byte m_ghash;
		size_t m_ad_len = 0, m_text_len = 0;
};