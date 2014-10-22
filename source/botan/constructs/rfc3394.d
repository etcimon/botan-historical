/*
* AES Key Wrap (RFC 3394)
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.rfc3394;

import botan.algo_base.symkey;
import botan.algo_factory.algo_factory;
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.algo_factory.algo_factory;
import botan.utils.types;

/**
* Encrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* @param key the plaintext key to encrypt
* @param kek the key encryption key
* @param af an algorithm factory
* @return key encrypted under kek
*/
SafeVector!ubyte rfc3394_keywrap(in SafeVector!ubyte key,
                                 const ref SymmetricKey kek,
                                 AlgorithmFactory af)
{
	if (key.length % 8 != 0)
		throw new Invalid_Argument("Bad input key size for NIST key wrap");
	
	Unique!BlockCipher aes = make_aes(kek.length(), af);
	aes.set_key(kek);
	
	const size_t n = key.length / 8;
	
	SafeVector!ubyte R = SafeVector!ubyte((n + 1) * 8);
	SafeVector!ubyte A = SafeVector!ubyte(16);
	
	for (size_t i = 0; i != 8; ++i)
		A[i] = 0xA6;
	
	copy_mem(&R[8], &key[0], key.length);
	
	for (size_t j = 0; j <= 5; ++j)
	{
		for (size_t i = 1; i <= n; ++i)
		{
			const uint t = (n * j) + i;
			
			copy_mem(&A[8], &R[8*i], 8);
			
			aes.encrypt(&A[0]);
			copy_mem(&R[8*i], &A[8], 8);
			
			ubyte[4] t_buf;
			store_be(t, t_buf);
			xor_buf(&A[4], &t_buf[0], 4);
		}
	}
	
	copy_mem(&R[0], &A[0], 8);
	
	return R;
}

/**
* Decrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* @param key the encrypted key to decrypt
* @param kek the key encryption key
* @param af an algorithm factory
* @return key decrypted under kek
*/
SafeVector!ubyte rfc3394_keyunwrap(in SafeVector!ubyte key,
                                   const ref SymmetricKey kek,
                                   AlgorithmFactory af)
{
	if (key.length < 16 || key.length % 8 != 0)
		throw new Invalid_Argument("Bad input key size for NIST key unwrap");
	
	Unique!BlockCipher aes = make_aes(kek.length(), af);
	aes.set_key(kek);
	
	const size_t n = (key.length - 8) / 8;
	
	SafeVector!ubyte R = SafeVector!ubyte(n * 8);
	SafeVector!ubyte A = SafeVector!ubyte(16);
	
	for (size_t i = 0; i != 8; ++i)
		A[i] = key[i];
	
	copy_mem(&R[0], &key[8], key.length - 8);
	
	for (size_t j = 0; j <= 5; ++j)
	{
		for (size_t i = n; i != 0; --i)
		{
			const uint t = (5 - j) * n + i;
			
			ubyte[4] t_buf;
			store_be(t, t_buf);
			
			xor_buf(&A[4], &t_buf[0], 4);
			
			copy_mem(&A[8], &R[8*(i-1)], 8);
			
			aes.decrypt(&A[0]);
			
			copy_mem(&R[8*(i-1)], &A[8], 8);
		}
	}
	
	if (load_be!ulong(&A[0], 0) != 0xA6A6A6A6A6A6A6A6)
		throw new Integrity_Failure("NIST key unwrap failed");
	
	return R;
}


private:

BlockCipher make_aes(size_t keylength,
                     AlgorithmFactory af)
{
	if (keylength == 16)
		return af.make_block_cipher("AES-128");
	else if (keylength == 24)
		return af.make_block_cipher("AES-192");
	else if (keylength == 32)
		return af.make_block_cipher("AES-256");
	else
		throw new Invalid_Argument("Bad KEK length for NIST keywrap");
}