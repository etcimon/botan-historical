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
class OCB_Mode : AEAD_Mode
{
	public:
		override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len);

		override void set_associated_data(in ubyte* ad, size_t ad_len);

		override string name() const;

		override size_t update_granularity() const;

		override Key_Length_Specification key_spec() const;

		override bool valid_nonce_length(size_t) const;

		override size_t tag_size() const { return m_tag_size; }

		override void clear();

		~this();
	package:
		/**
		* @param cipher the 128-bit block cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		OCB_Mode(BlockCipher cipher, size_t tag_size);

		override void key_schedule(in ubyte* key, size_t length);

		// fixme make these private
		Unique!BlockCipher m_cipher;
		Unique!L_computer m_L;

		size_t m_block_index = 0;

		SafeVector!ubyte m_checksum;
		SafeVector!ubyte m_offset;
		SafeVector!ubyte m_ad_hash;
	private:
		SafeVector!ubyte update_nonce(in ubyte* nonce, size_t nonce_len);

		size_t m_tag_size = 0;
		SafeVector!ubyte m_last_nonce;
		SafeVector!ubyte m_stretch;
};

class OCB_Encryption : OCB_Mode
{
	public:
		/**
		* @param cipher the 128-bit block cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		OCB_Encryption(BlockCipher cipher, size_t tag_size = 16) :
			OCB_Mode(cipher, tag_size) {}

		override size_t output_length(size_t input_length) const
		{ return input_length + tag_size(); }

		override size_t minimum_final_size() const { return 0; }

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);
	private:
		void encrypt(ubyte* input, size_t blocks);
};

class OCB_Decryption : OCB_Mode
{
	public:
		/**
		* @param cipher the 128-bit block cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		OCB_Decryption(BlockCipher cipher, size_t tag_size = 16) :
			OCB_Mode(cipher, tag_size) {}

		override size_t output_length(size_t input_length) const
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		override size_t minimum_final_size() const { return tag_size(); }

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);
	private:
		void decrypt(ubyte* input, size_t blocks);
};