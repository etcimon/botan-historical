/*
* AES Key Wrap (RFC 3394)
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.rfc3394;
import botan.algo_factory;
import botan.block_cipher;
import botan.loadstor;
import botan.exceptn;
import botan.internal.xor_buf;
namespace {

BlockCipher make_aes(size_t keylength,
							 Algorithm_Factory af)
{
	if (keylength == 16)
		return af.make_block_cipher("AES-128");
	else if (keylength == 24)
		return af.make_block_cipher("AES-192");
	else if (keylength == 32)
		return af.make_block_cipher("AES-256");
	else
		throw new std::invalid_argument("Bad KEK length for NIST keywrap");
}

}

SafeVector!ubyte rfc3394_keywrap(in SafeVector!ubyte key,
												const SymmetricKey& kek,
												Algorithm_Factory af)
{
	if (key.size() % 8 != 0)
		throw new std::invalid_argument("Bad input key size for NIST key wrap");

	Unique!BlockCipher aes = make_aes(kek.length(), af);
	aes.set_key(kek);

	const size_t n = key.size() / 8;

	SafeVector!ubyte R((n + 1) * 8);
	SafeVector!ubyte A(16);

	for (size_t i = 0; i != 8; ++i)
		A[i] = 0xA6;

	copy_mem(&R[8], &key[0], key.size());

	for (size_t j = 0; j <= 5; ++j)
	{
		for (size_t i = 1; i <= n; ++i)
		{
			const uint t = (n * j) + i;

			copy_mem(&A[8], &R[8*i], 8);

			aes.encrypt(&A[0]);
			copy_mem(&R[8*i], &A[8], 8);

			ubyte[4] t_buf = { 0 };
			store_be(t, t_buf);
			xor_buf(&A[4], &t_buf[0], 4);
		}
	}

	copy_mem(&R[0], &A[0], 8);

	return R;
}

SafeVector!ubyte rfc3394_keyunwrap(in SafeVector!ubyte key,
												 const SymmetricKey& kek,
												 Algorithm_Factory af)
{
	if (key.size() < 16 || key.size() % 8 != 0)
		throw new std::invalid_argument("Bad input key size for NIST key unwrap");

	Unique!BlockCipher aes(make_aes(kek.length(), af));
	aes.set_key(kek);

	const size_t n = (key.size() - 8) / 8;

	SafeVector!ubyte R(n * 8);
	SafeVector!ubyte A(16);

	for (size_t i = 0; i != 8; ++i)
		A[i] = key[i];

	copy_mem(&R[0], &key[8], key.size() - 8);

	for (size_t j = 0; j <= 5; ++j)
	{
		for (size_t i = n; i != 0; --i)
		{
			const uint t = (5 - j) * n + i;

			ubyte[4] t_buf = { 0 };
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

}
