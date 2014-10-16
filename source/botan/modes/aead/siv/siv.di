/*
* SIV Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.aead;
import botan.block.block_cipher;
import botan.stream_cipher;
import botan.mac.mac;
/**
* Base class for SIV encryption and decryption (@see RFC 5297)
*/
class SIV_Mode : AEAD_Mode
{
	public:
		override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len);

		override void update(SafeVector!ubyte blocks, size_t offset = 0);

		void set_associated_data_n(size_t n, in ubyte* ad, size_t ad_len);

		override void set_associated_data(in ubyte* ad, size_t ad_len)
		{
			set_associated_data_n(0, ad, ad_len);
		}

		override string name() const;

		override size_t update_granularity() const;

		override Key_Length_Specification key_spec() const;

		override bool valid_nonce_length(size_t) const;

		override void clear();

		override size_t tag_size() const { return 16; }

	package:
		SIV_Mode(BlockCipher cipher);

		StreamCipher& ctr() { return *m_ctr; }

		void set_ctr_iv(SafeVector!ubyte V);

		SafeVector!ubyte msg_buf() { return m_msg_buf; }

		SafeVector!ubyte S2V(in ubyte* text, size_t text_len);
	private:
		MessageAuthenticationCode cmac() { return *m_cmac; }

		override void key_schedule(in ubyte* key, size_t length);

		const string m_name;

		Unique!StreamCipher m_ctr;
		Unique!MessageAuthenticationCode m_cmac;
		SafeVector!ubyte m_nonce, m_msg_buf;
		Vector!( SafeVector!ubyte ) m_ad_macs;
};

/**
* SIV Encryption
*/
class SIV_Encryption : SIV_Mode
{
	public:
		/**
		* @param cipher a block cipher
		*/
		SIV_Encryption(BlockCipher cipher) : SIV_Mode(cipher) {}

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t output_length(size_t input_length) const
		{ return input_length + tag_size(); }

		override size_t minimum_final_size() const { return 0; }
};

/**
* SIV Decryption
*/
class SIV_Decryption : SIV_Mode
{
	public:
		/**
		* @param cipher a 128-bit block cipher
		*/
		SIV_Decryption(BlockCipher cipher) : SIV_Mode(cipher) {}

		override void finish(SafeVector!ubyte final_block, size_t offset = 0);

		override size_t output_length(size_t input_length) const
		{
			BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
			return input_length - tag_size();
		}

		override size_t minimum_final_size() const { return tag_size(); }
};