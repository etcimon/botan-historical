/*
* Blowfish
* (C) 1999-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
/**
* Blowfish
*/
class Blowfish : public Block_Cipher_Fixed_Params<8, 1, 56>
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const;
		void decrypt_n(in byte[] input, ref byte[] output) const;

		/**
		* Modified EKSBlowfish key schedule, used for bcrypt password hashing
		*/
		void eks_key_schedule(in byte[] key, size_t key_length,
									 const byte salt[16], size_t workfactor);

		void clear();
		string name() const { return "Blowfish"; }
		BlockCipher* clone() const { return new Blowfish; }
	private:
		void key_schedule(in byte[] key);

		void key_expansion(in byte[] key,
								 size_t key_length,
								 const byte salt[16]);

		void generate_sbox(secure_vector<uint>& box,
								 ref uint L, ref uint R,
								 const byte salt[16],
								 size_t salt_off) const;

		static const uint P_INIT[18];
		static const uint S_INIT[1024];

		secure_vector<uint> S, P;
};