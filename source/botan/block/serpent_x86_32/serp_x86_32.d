/*
* Serpent in x86-32
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.serp_x86_32;
import botan.loadstor;
extern "C" {

/**
* Entry point for Serpent encryption in x86 asm
* @param in the input block
* @param out the output block
* @param ks the key schedule
*/
void botan_serpent_x86_32_encrypt(const byte[16] input,
										  byte[16] output,
										  const uint[132] ks);

/**
* Entry point for Serpent decryption in x86 asm
* @param in the input block
* @param out the output block
* @param ks the key schedule
*/
void botan_serpent_x86_32_decrypt(const byte[16] input,
										  byte[16] output,
										  const uint[132] ks);

/**
* Entry point for Serpent key schedule in x86 asm
* @param ks holds the initial working key (padded), and is set to the
				final key schedule
*/
void botan_serpent_x86_32_key_schedule(uint[140] ks);

}

/*
* Serpent Encryption
*/
void Serpent_X86_32::encrypt_n(byte* input, byte* output, size_t blocks) const
{
	auto keys = this.get_round_keys();

	for (size_t i = 0; i != blocks; ++i)
	{
		botan_serpent_x86_32_encrypt(input, output, &keys[0]);
		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* Serpent Decryption
*/
void Serpent_X86_32::decrypt_n(byte* input, byte* output, size_t blocks) const
{
	auto keys = this.get_round_keys();

	for (size_t i = 0; i != blocks; ++i)
	{
		botan_serpent_x86_32_decrypt(input, output, &keys[0]);
		input += BLOCK_SIZE;
		output += BLOCK_SIZE;
	}
}

/*
* Serpent Key Schedule
*/
void Serpent_X86_32::key_schedule(in byte* key)
{
	secure_vector!uint W(140);
	for (size_t i = 0; i != length / 4; ++i)
		W[i] = load_le!uint(key, i);
	W[length / 4] |= uint(1) << ((length%4)*8);

	botan_serpent_x86_32_key_schedule(&W[0]);
	this.set_round_keys(&W[8]);
}

}
