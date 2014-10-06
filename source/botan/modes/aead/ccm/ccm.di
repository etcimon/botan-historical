/*
* CCM Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.aead;
import botan.block_cipher;
import botan.stream_cipher;
import botan.mac;
/**
* Base class for CCM encryption and decryption
* @see RFC 3610
*/
class CCM_Mode : AEAD_Mode
{
	public:
		override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len);

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void set_associated_data(in ubyte* ad, size_t ad_len);

		override string name() const;

		size_t update_granularity() const;

		override Key_Length_Specification key_spec() const;

		override bool valid_nonce_length(size_t) const;

		override size_t default_nonce_length() const;

		override void clear();

		size_t tag_size() const { return m_tag_size; }

	package:
		const size_t BS = 16; // intrinsic to CCM definition

		CCM_Mode(BlockCipher cipher, size_t tag_size, size_t L);

		size_t L() const { return m_L; }

		const BlockCipher& cipher() const { return *m_cipher; }

		void encode_length(size_t len, ubyte* output);

		void inc(SafeVector!ubyte C);

		in SafeVector!ubyte ad_buf() const { return m_ad_buf; }

		SafeVector!ubyte msg_buf() { return m_msg_buf; }

		SafeVector!ubyte format_b0(size_t msg_size);
		SafeVector!ubyte format_c0();
	private:
		override void key_schedule(in ubyte* key, size_t length);

		const size_t m_tag_size;
		const size_t m_L;

		Unique!BlockCipher m_cipher;
		SafeVector!ubyte m_nonce, m_msg_buf, m_ad_buf;
};

/**
* CCM Encryption
*/
class CCM_Encryption : CCM_Mode
{
	public:
		/**
		* @param cipher a 128-bit block cipher
		* @param tag_size is how big the auth tag will be (even values
		*					  between 4 and 16 are accepted)
		* @param L length of L parameter. The total message length
		*			  must be less than 2**L bytes, and the nonce is 15-L bytes.
		*/
		CCM_Encryption(BlockCipher cipher, size_t tag_size = 16, size_t L = 3) :
			CCM_Mode(cipher, tag_size, L) {}

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t output_length(size_t input_length) const
		{ return input_length + tag_size(); }

		override size_t minimum_final_size() const { return 0; }
};

/**
* CCM Decryption
*/
class CCM_Decryption : CCM_Mode
{
	public:
		/**
		* @param cipher a 128-bit block cipher
		* @param tag_size is how big the auth tag will be (even values
		*					  between 4 and 16 are accepted)
		* @param L length of L parameter. The total message length
		*			  must be less than 2**L bytes, and the nonce is 15-L bytes.
		*/
		CCM_Decryption(BlockCipher cipher, size_t tag_size = 16, size_t L = 3) :
			CCM_Mode(cipher, tag_size, L) {}

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t output_length(size_t input_length) const
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		override size_t minimum_final_size() const { return tag_size(); }
};