/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "tests.h"
#include "test_rng.h"
#include "test_pubkey.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <memory>

#include <botan/oids.h>

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)
  #include <botan/x509_key.h>
  #include <botan/pkcs8.h>
  #include <botan/pubkey.h>
  #include <botan/auto_rng.h>
#endif

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
#endif

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
#endif

#if defined(BOTAN_HAS_DLIES)
  #include <botan/dlies.h>
  #include <botan/kdf.h>
#endif

#include <botan/filters.h>
#include <botan/numthry.h>


void dump_data(const Vector!ubyte output,
				const Vector!ubyte expected)
{
	Pipe pipe = Pipe(new Hex_Encoder);

	pipe.process_msg(output);
	pipe.process_msg(expected);
	writeln("Got: " ~ pipe.read_all_as_string(0));
	writeln("Exp: " ~ pipe.read_all_as_string(1));
}

size_t validate_save_and_load(const Private_Key priv_key,
								RandomNumberGenerator rng)
{
	string name = priv_key.algo_name();

	size_t fails = 0;
	string pub_pem = x509_key.PEM_encode(priv_key);

	try
	{
		DataSource_Memory input_pub = scoped!DataSource_Memory(pub_pem);
		Public_Key restored_pub = x509_key.load_key(input_pub);

		if (!restored_pub)
		{
			writeln("Could not recover " ~ name ~ " public key");
			++fails;
		}
		else if (restored_pub.check_key(rng, true) == false)
		{
			writeln("Restored pubkey failed self tests " ~ name);
			++fails;
		}
	}
	catch(Exception e)
	{
		writeln("Exception during load of " ~ name ~ " key: " ~ e.msg);
		writeln("PEM for pubkey was: " ~ pub_pem);
		++fails;
	}

	string priv_pem = pkcs8.PEM_encode(priv_key);

	try
	{
		auto input_priv = scoped!DataSource_Memory(priv_pem);
		Unique!Private_Key restored_priv = pkcs8.load_key(input_priv, rng);

		if (!restored_priv)
		{
			writeln("Could not recover " ~ name ~ " private key");
			++fails;
		}
		else if (restored_priv.check_key(rng, true) == false)
		{
			writeln("Restored privkey failed self tests " ~ name);
			++fails;
		}
	}
	catch(Exception e)
	{
		writeln("Exception during load of " ~ name ~ " key: " ~ e.msg);
		writeln("PEM for privkey was: " ~ priv_pem);
		++fails;
	}

	return fails;
}

ubyte nonzero_byte(RandomNumberGenerator rng)
{
	ubyte b = 0;
	while(b == 0)
		b = rng.next_byte();
	return b;
}

string PK_TEST(string expr, string msg) 
{
	return `
		{
			const bool test_result = ` ~ expr ~ `;
			if (!test_result)
			{
				writeln("Test " ~ ` ~ expr ~ ` ~ " failed: " ~ msg);
				++fails;
			}
		}
	`;
}

size_t validate_encryption(PK_Encryptor e, PK_Decryptor d,
									string algo, string input,
									string random, string exp)
{
	Vector!ubyte message = hex_decode(input);
	Vector!ubyte expected = hex_decode(exp);
	Fixed_Output_RNG rng = scoped!Fixed_Output_RNG(hex_decode(random));

	size_t fails = 0;

	const Vector!ubyte ctext = e.encrypt(message, rng);
	if (ctext != expected)
	{
		writeln("FAILED (encrypt): " ~ algo);
		dump_data(ctext, expected);
		++fails;
	}

	Vector!ubyte decrypted = unlock(d.decrypt(ctext));

	if (decrypted != message)
	{
		writeln("FAILED (decrypt): " ~ algo);
		dump_data(decrypted, message);
		++fails;
	}

	if (algo.canFind("/Raw") == -1)
	{
		AutoSeeded_RNG rng;

		for(size_t i = 0; i != ctext.length; ++i)
		{
			Vector!ubyte bad_ctext = ctext;

			bad_ctext[i] ^= nonzero_byte(rng);

			assert(bad_ctext != ctext, "Made them different");

			try
			{
				auto bad_ptext = unlock(d.decrypt(bad_ctext));
				writeln(algo ~ " failed - decrypted bad data");
				writeln(hex_encode(bad_ctext) ~ " . " ~ hex_encode(bad_ptext));
				writeln(hex_encode(ctext) ~ " . " ~ hex_encode(decrypted));
				++fails;
			}
			catch {}
		}
	}

	return fails;
}

size_t validate_signature(PK_Verifier v, PK_Signer s, string algo,
								  string input,
								  RandomNumberGenerator rng,
								  string exp)
{
	return validate_signature(v, s, algo, input, rng, rng, exp);
}

size_t validate_signature(PK_Verifier v, PK_Signer s, string algo,
								  string input,
								  RandomNumberGenerator signer_rng,
								  RandomNumberGenerator test_rng,
								  string exp)	
{
	Vector!ubyte message = hex_decode(input);
	Vector!ubyte expected = hex_decode(exp);
	Vector!ubyte sig = s.sign_message(message, signer_rng);

	size_t fails = 0;

	if (sig != expected)
	{
		writeln("FAILED (sign): " ~ algo);
		dump_data(sig, expected);
		++fails;
	}

	mixin( PK_TEST(` v.verify_message(message, sig) `, "Correct signature is valid") );

	zero_mem(&sig[0], sig.length);

	mixin( PK_TEST(` !v.verify_message(message, sig) `, "All-zero signature is invalid") );

	for(size_t i = 0; i != 3; ++i)
	{
		auto bad_sig = sig;

		const size_t idx = (test_rng.next_byte() * 256 + test_rng.next_byte()) % sig.length;
		bad_sig[idx] ^= nonzero_byte(test_rng);

		mixin( PK_TEST(` !v.verify_message(message, bad_sig) `, "Incorrect signature is invalid") );
	}

	return fails;
}

size_t validate_signature(PK_Verifier v, PK_Signer s, string algo,
								  string input,
								  RandomNumberGenerator rng,
								  string random,
								  string exp)
{
	Fixed_Output_RNG fixed_rng = scoped!Fixed_Output_RNG(hex_decode(random));

	return validate_signature(v, s, algo, input, fixed_rng, rng, exp);
}

size_t validate_kas(PK_Key_Agreement kas, string algo,
						  const Vector!ubyte pubkey, string output,
						  size_t keylen)
{
	Vector!ubyte expected = hex_decode(output);

	Vector!ubyte got = unlock(kas.derive_key(keylen, pubkey).bits_of());

	size_t fails = 0;

	if (got != expected)
			{
		writeln("FAILED: " ~ algo);
		dump_data(got, expected);
		++fails;
	}

	return fails;
}

size_t test_pk_keygen()	
{
	AutoSeeded_RNG rng;

	size_t tests = 0;
	size_t fails = 0;

#define DL_KEY(TYPE, GROUP)									 	{																	 \
	TYPE key(rng, DL_Group(GROUP));							 \
	key.check_key(rng, true);									 \
	++tests;															\
	fails += validate_save_and_load(&key, rng);			 \
}

#define EC_KEY(TYPE, GROUP)									  	{																	 \
	TYPE key(rng, EC_Group(OIDS.lookup(GROUP)));		  \
	key.check_key(rng, true);									 \
	++tests;															\
	fails += validate_save_and_load(&key, rng);			 \
}

#if defined(BOTAN_HAS_RSA)	{
		RSA_PrivateKey rsa1024(rng, 1024);
		rsa1024.check_key(rng, true);
		++tests;
		fails += validate_save_and_load(&rsa1024, rng);

		RSA_PrivateKey rsa2048(rng, 2048);
		rsa2048.check_key(rng, true);
		++tests;
		fails += validate_save_and_load(&rsa2048, rng);
	}
#endif

#if defined(BOTAN_HAS_RW)	{
		RW_PrivateKey rw1024(rng, 1024);
		rw1024.check_key(rng, true);
		++tests;
		fails += validate_save_and_load(&rw1024, rng);
	}
#endif

#if defined(BOTAN_HAS_DSA)
	DL_KEY(DSA_PrivateKey, "dsa/jce/1024");
	DL_KEY(DSA_PrivateKey, "dsa/botan/2048");
	DL_KEY(DSA_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
	DL_KEY(DH_PrivateKey, "modp/ietf/1024");
	DL_KEY(DH_PrivateKey, "modp/ietf/2048");
	DL_KEY(DH_PrivateKey, "modp/ietf/4096");
	DL_KEY(DH_PrivateKey, "dsa/jce/1024");
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
	DL_KEY(NR_PrivateKey, "dsa/jce/1024");
	DL_KEY(NR_PrivateKey, "dsa/botan/2048");
	DL_KEY(NR_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_ELGAMAL)
	DL_KEY(ElGamal_PrivateKey, "modp/ietf/1024");
	DL_KEY(ElGamal_PrivateKey, "dsa/jce/1024");
	DL_KEY(ElGamal_PrivateKey, "dsa/botan/2048");
	DL_KEY(ElGamal_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_ECDSA)
	EC_KEY(ECDSA_PrivateKey, "secp112r1");
	EC_KEY(ECDSA_PrivateKey, "secp128r1");
	EC_KEY(ECDSA_PrivateKey, "secp160r1");
	EC_KEY(ECDSA_PrivateKey, "secp192r1");
	EC_KEY(ECDSA_PrivateKey, "secp224r1");
	EC_KEY(ECDSA_PrivateKey, "secp256r1");
	EC_KEY(ECDSA_PrivateKey, "secp384r1");
	EC_KEY(ECDSA_PrivateKey, "secp521r1");
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
	EC_KEY(GOST_3410_PrivateKey, "gost_256A");
	EC_KEY(GOST_3410_PrivateKey, "secp112r1");
	EC_KEY(GOST_3410_PrivateKey, "secp128r1");
	EC_KEY(GOST_3410_PrivateKey, "secp160r1");
	EC_KEY(GOST_3410_PrivateKey, "secp192r1");
	EC_KEY(GOST_3410_PrivateKey, "secp224r1");
	EC_KEY(GOST_3410_PrivateKey, "secp256r1");
	EC_KEY(GOST_3410_PrivateKey, "secp384r1");
	EC_KEY(GOST_3410_PrivateKey, "secp521r1");
#endif

	test_report("PK keygen", tests, fails);

	return fails;
}
