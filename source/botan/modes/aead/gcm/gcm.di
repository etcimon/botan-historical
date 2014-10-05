/*
* GCM Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.aead;
import botan.block_cipher;
import botan.stream_cipher;
class GHASH;

/**
* GCM Mode
*/
class GCM_Mode : public AEAD_Mode
{
	public:
		SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len) override;

		void set_associated_data(in ubyte* ad, size_t ad_len) override;

		string name() const override;

		size_t update_granularity() const;

		Key_Length_Specification key_spec() const override;

		// GCM supports arbitrary nonce lengths
		bool valid_nonce_length(size_t) const override { return true; }

		size_t tag_size() const override { return m_tag_size; }

		void clear() override;
	package:
		void key_schedule(in ubyte* key, size_t length) override;

		GCM_Mode(BlockCipher cipher, size_t tag_size);

		const size_t BS = 16;

		const size_t m_tag_size;
		const string m_cipher_name;

		Unique!StreamCipher m_ctr;
		Unique!GHASH m_ghash;
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
		GCM_Encryption(BlockCipher cipher, size_t tag_size = 16) :
			GCM_Mode(cipher, tag_size) {}

		size_t output_length(size_t input_length) const override
		{ return input_length + tag_size(); }

		size_t minimum_final_size() const override { return 0; }

		void update(SafeVector!ubyte blocks, size_t offset = 0) override;

		void finish(SafeVector!ubyte final_block, size_t offset = 0) override;
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
		GCM_Decryption(BlockCipher cipher, size_t tag_size = 16) :
			GCM_Mode(cipher, tag_size) {}

		size_t output_length(size_t input_length) const override
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		size_t minimum_final_size() const override { return tag_size(); }

		void update(SafeVector!ubyte blocks, size_t offset = 0) override;

		void finish(SafeVector!ubyte final_block, size_t offset = 0) override;
};

/**
* GCM's GHASH
* Maybe a Transform?
*/
class GHASH : public SymmetricAlgorithm
{
	public:
		void set_associated_data(in ubyte* ad, size_t ad_len);

		SafeVector!ubyte nonce_hash(in ubyte* nonce, size_t len);

		void start(in ubyte* nonce, size_t len);

		/*
		* Assumes input len is multiple of 16
		*/
		void update(in ubyte* input, size_t length);

		SafeVector!ubyte flush();

		Key_Length_Specification key_spec() const { return Key_Length_Specification(16); }

		void clear() override;

		string name() const { return "GHASH"; }
	private:
		void key_schedule(in ubyte* key, size_t length) override;

		void gcm_multiply(SafeVector!ubyte x) const;

		void ghash_update(SafeVector!ubyte x,
								in ubyte* input, size_t input_len);

		void add_final_block(SafeVector!ubyte x,
									size_t ad_len, size_t pt_len);

		SafeVector!ubyte m_H;
		SafeVector!ubyte m_H_ad;
		SafeVector!ubyte m_nonce;
		SafeVector!ubyte m_ghash;
		size_t m_ad_len = 0, m_text_len = 0;
};