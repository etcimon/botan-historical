/*
* Threefish
* (C) 2013,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* Threefish-512
*/
class Threefish_512 : public Block_Cipher_Fixed_Params!(64, 64)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const override;
		void decrypt_n(byte* input, byte* output, size_t blocks) const override;

		void set_tweak(in byte* tweak, size_t len);

		void clear() override;
		string name() const override { return "Threefish-512"; }
		BlockCipher* clone() const override { return new Threefish_512; }

		Threefish_512() : m_T(3) {}

	protected:
		const secure_vector!ulong& get_T() const { return m_T; }
		const secure_vector!ulong& get_K() const { return m_K; }
	private:
		void key_schedule(in byte* key) override;

		// Interface for Skein
		friend class Skein_512;

		abstract void skein_feedfwd(in secure_vector!ulong M,
											const secure_vector!ulong& T);

		// Private data
		secure_vector!ulong m_T;
		secure_vector!ulong m_K;
};