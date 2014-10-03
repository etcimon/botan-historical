/*
* OCB Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.aead;
import botan.block_cipher;
import botan.buf_filt;
class L_computer;

/**
* OCB Mode (base class for OCB_Encryption and OCB_Decryption). Note
* that OCB is patented, but is freely licensed in some circumstances.
*
* @see "The OCB Authenticated-Encryption Algorithm" internet draft
		  http://tools.ietf.org/html/draft-irtf-cfrg-ocb-03
* @see Free Licenses http://www.cs.ucdavis.edu/~rogaway/ocb/license.htm
* @see OCB home page http://www.cs.ucdavis.edu/~rogaway/ocb
*/
class OCB_Mode : public AEAD_Mode
{
	public:
		SafeVector!byte start(in byte* nonce, size_t nonce_len) override;

		void set_associated_data(in byte* ad, size_t ad_len) override;

		string name() const override;

		size_t update_granularity() const override;

		Key_Length_Specification key_spec() const override;

		bool valid_nonce_length(size_t) const override;

		size_t tag_size() const override { return m_tag_size; }

		void clear() override;

		~this();
	package:
		/**
		* @param cipher the 128-bit block cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		OCB_Mode(BlockCipher cipher, size_t tag_size);

		void key_schedule(in byte* key, size_t length) override;

		// fixme make these private
		Unique!BlockCipher m_cipher;
		Unique!L_computer m_L;

		size_t m_block_index = 0;

		SafeVector!byte m_checksum;
		SafeVector!byte m_offset;
		SafeVector!byte m_ad_hash;
	private:
		SafeVector!byte update_nonce(in byte* nonce, size_t nonce_len);

		size_t m_tag_size = 0;
		SafeVector!byte m_last_nonce;
		SafeVector!byte m_stretch;
};

class OCB_Encryption : public OCB_Mode
{
	public:
		/**
		* @param cipher the 128-bit block cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		OCB_Encryption(BlockCipher cipher, size_t tag_size = 16) :
			OCB_Mode(cipher, tag_size) {}

		size_t output_length(size_t input_length) const override
		{ return input_length + tag_size(); }

		size_t minimum_final_size() const override { return 0; }

		void update(SafeVector!byte blocks, size_t offset = 0) override;

		void finish(SafeVector!byte final_block, size_t offset = 0) override;
	private:
		void encrypt(byte* input, size_t blocks);
};

class OCB_Decryption : public OCB_Mode
{
	public:
		/**
		* @param cipher the 128-bit block cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		OCB_Decryption(BlockCipher cipher, size_t tag_size = 16) :
			OCB_Mode(cipher, tag_size) {}

		size_t output_length(size_t input_length) const override
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		size_t minimum_final_size() const override { return tag_size(); }

		void update(SafeVector!byte blocks, size_t offset = 0) override;

		void finish(SafeVector!byte final_block, size_t offset = 0) override;
	private:
		void decrypt(byte* input, size_t blocks);
};