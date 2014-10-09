/*
* Threefish
* (C) 2013,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block.block_cipher;
/**
* Threefish-512
*/
class Threefish_512 : Block_Cipher_Fixed_Params!(64, 64)
{
	public:
		override void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const;
		override void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const;

		void set_tweak(in ubyte* tweak, size_t len);

		override void clear();
		override string name() const { return "Threefish-512"; }
		override BlockCipher clone() const { return new Threefish_512; }

		Threefish_512() : m_T(3) {}

	package:
		const secure_vector!ulong& get_T() const { return m_T; }
		const secure_vector!ulong& get_K() const { return m_K; }
	private:
		override void key_schedule(in ubyte* key);

		// Interface for Skein
		friend class Skein_512;

		abstract void skein_feedfwd(in secure_vector!ulong M,
											const secure_vector!ulong& T);

		// Private data
		secure_vector!ulong m_T;
		secure_vector!ulong m_K;
};