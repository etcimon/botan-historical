/*
* EAX Mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.aead;
import botan.block.block_cipher;
import botan.stream_cipher;
import botan.mac;
/**
* EAX base class
*/
class EAX_Mode : AEAD_Mode
{
	public:
		override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len);

		override void set_associated_data(in ubyte* ad, size_t ad_len);

		override string name() const;

		override size_t update_granularity() const;

		override Key_Length_Specification key_spec() const;

		// EAX supports arbitrary nonce lengths
		override bool valid_nonce_length(size_t) const { return true; }

		override size_t tag_size() const { return m_tag_size; }

		override void clear();
	package:
		override void key_schedule(in ubyte* key, size_t length);

		/**
		* @param cipher the cipher to use
		* @param tag_size is how big the auth tag will be
		*/
		EAX_Mode(BlockCipher cipher, size_t tag_size);

		size_t block_size() const { return m_cipher.block_size(); }

		size_t m_tag_size;

		Unique!BlockCipher m_cipher;
		Unique!StreamCipher m_ctr;
		Unique!MessageAuthenticationCode m_cmac;

		SafeVector!ubyte m_ad_mac;

		SafeVector!ubyte m_nonce_mac;
};

/**
* EAX Encryption
*/
class EAX_Encryption : EAX_Mode
{
	public:
		/**
		* @param cipher a 128-bit block cipher
		* @param tag_size is how big the auth tag will be
		*/
		EAX_Encryption(BlockCipher cipher, size_t tag_size = 0) :
			EAX_Mode(cipher, tag_size) {}

		override size_t output_length(size_t input_length) const
		{ return input_length + tag_size(); }

		override size_t minimum_final_size() const { return 0; }

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);
};

/**
* EAX Decryption
*/
class EAX_Decryption : EAX_Mode
{
	public:
		/**
		* @param cipher a 128-bit block cipher
		* @param tag_size is how big the auth tag will be
		*/
		EAX_Decryption(BlockCipher cipher, size_t tag_size = 0) :
			EAX_Mode(cipher, tag_size) {}

		override size_t output_length(size_t input_length) const
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		override size_t minimum_final_size() const { return tag_size(); }

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);
};