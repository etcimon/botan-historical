/*
* SEED
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* SEED, a Korean block cipher
*/
class SEED : public Block_Cipher_Fixed_Params!(16, 16)
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();
		string name() const { return "SEED"; }
		BlockCipher* clone() const { return new SEED; }
	private:
		void key_schedule(in byte*, size_t);

		class G_FUNC
		{
			public:
				uint operator()(uint) const;
			private:
				static const uint S0[256], S1[256], S2[256], S3[256];
		};

		secure_vector!uint K;
};