
#include "tests.h"
#include <iostream>

#if defined(BOTAN_HAS_OCB)
#include <botan/ocb.h>
#include <botan/hex.h>
#include <botan/sha2_32.h>
#include <botan/aes.h>



// something like this should be in the library
namespace {

Vector!ubyte ocb_decrypt(in SymmetricKey key,
							in Vector!ubyte nonce,
							in ubyte* ct, size_t ct_len,
							in ubyte* ad, size_t ad_len)
{
	OCB_Decryption ocb(new AES_128);

	ocb.set_key(key);
	ocb.set_associated_data(ad, ad_len);

	ocb.start(&nonce[0], nonce.length);

	Secure_Vector!ubyte buf(ct, ct+ct_len);
	ocb.finish(buf, 0);

	return unlock(buf);
}

Vector!ubyte ocb_encrypt(in SymmetricKey key,
							in Vector!ubyte nonce,
							in ubyte* pt, size_t pt_len,
							in ubyte* ad, size_t ad_len)
{
	OCB_Encryption ocb(new AES_128);

	ocb.set_key(key);
	ocb.set_associated_data(ad, ad_len);

	ocb.start(&nonce[0], nonce.length);

	Secure_Vector!ubyte buf(pt, pt+pt_len);
	ocb.finish(buf, 0);

	try
	{
		Vector!ubyte pt2 = ocb_decrypt(key, nonce, &buf[0], buf.length, ad, ad_len);
		if (pt_len != pt2.length || !same_mem(pt, &pt2[0], pt_len))
			writeln("OCB failed to decrypt correctly");
	}
	catch(Exception e)
	{
		writeln("OCB round trip error - " ~ e.msg);
	}

	return unlock(buf);
}

Vector!ubyte ocb_encrypt(Alloc, Alloc2)(in SymmetricKey key,
										in Vector!ubyte nonce,
										in Vector!(ubyte, Alloc) pt,
										in Vector!(ubyte, Alloc2) ad)
{
	return ocb_encrypt(key, nonce, &pt[0], pt.length, &ad[0], ad.length);
}

Vector!ubyte ocb_decrypt(Alloc, Alloc2)(in SymmetricKey key,
										in Vector!ubyte nonce,
										in Vector!(ubyte, Alloc) pt,
										in Vector!(ubyte, Alloc2) ad)
{
	return ocb_decrypt(key, nonce, &pt[0], pt.length, &ad[0], ad.length);
}

Vector!ubyte ocb_encrypt(OCB_Encryption ocb,
										in Vector!ubyte nonce,
										in Vector!ubyte pt,
										in Vector!ubyte ad)
{
	ocb.set_associated_data(&ad[0], ad.length);

	ocb.start(&nonce[0], nonce.length);

	Secure_Vector!ubyte buf(pt.begin(), pt.end());
	ocb.finish(buf, 0);

	return unlock(buf);
}

size_t test_ocb_long(size_t taglen, in string expected)
{
	auto ocb = scoped!OCB_Encryption(new AES_128, taglen/8);

	ocb.set_key(SymmetricKey("00000000000000000000000000000000"));

	const Vector!ubyte empty;
	Vector!ubyte N = Vector!ubyte(12);
	Vector!ubyte C;

	for(size_t i = 0; i != 128; ++i)
	{
		const Vector!ubyte S = Vector!ubyte(i);
		N[11] = i;

		C ~= ocb_encrypt(ocb, N, S, S);
		C ~= ocb_encrypt(ocb, N, S, empty);
		C ~= ocb_encrypt(ocb, N, empty, S);
	}

	N[11] = 0;
	const Vector!ubyte cipher = ocb_encrypt(ocb, N, empty, C);

	const string cipher_hex = hex_encode(cipher);

	if (cipher_hex != expected)
	{
		writeln("OCB AES-128 long test mistmatch " ~ cipher_hex ~ " != " ~ expected);
		return 1;
	}

	return 0;
}

}
#endif

size_t test_ocb()
{
	size_t fails = 0;

#if defined(BOTAN_HAS_OCB)
	fails += test_ocb_long(128, "B2B41CBF9B05037DA7F16C24A35C1C94");
	fails += test_ocb_long(96, "1A4F0654277709A5BDA0D380");
	fails += test_ocb_long(64, "B7ECE9D381FE437F");
	test_report("OCB long", 3, fails);
#endif

	return fails;
}
