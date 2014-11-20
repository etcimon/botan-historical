#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>


size_t rsaes_kat(string e,
				  string p,
				  string q,
				  string msg,
				  string padding,
				  string nonce,
				  string output)
{
	AutoSeeded_RNG rng;

	auto privkey = scoped!RSA_PrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));

	auto pubkey = scoped!RSA_PublicKey(privkey);

	if (padding == "")
		padding = "Raw";

	auto enc = scoped!PK_Encryptor_EME(pubkey, padding);
	auto dec = scoped!PK_Decryptor_EME(privkey, padding);

	return validate_encryption(enc, dec, "RSAES/" ~ padding, msg, nonce, output);
}

size_t rsa_sig_kat(string e,
					  string p,
					  string q,
					  string msg,
					  string padding,
					  string nonce,
					  string output)
{
	AutoSeeded_RNG rng;

	auto privkey = scoped!RSA_PrivateKey(rng, BigInt(p), BigInt(q), BigInt(e));

	auto pubkey = scoped!RSA_PublicKey(privkey);

	if (padding == "")
		padding = "Raw";

	PK_Verifier verify = PK_Verifier(pubkey, padding);
	PK_Signer sign = PK_Signer(privkey, padding);

	return validate_signature(verify, sign, "RSA/" ~ padding, msg, rng, nonce, output);
}

size_t rsa_sig_verify(string e,
						 string n,
						 string msg,
						 string padding,
						 string signature)
{
	AutoSeeded_RNG rng;

	BigInt e_bn = BigInt(e);
	BigInt n_bn = BigInt(n);

	auto key = scoped!RSA_PublicKey(n_bn, e_bn);

	if (padding == "")
		padding = "Raw";

	PK_Verifier verify = PK_Verifier(key, padding);

	if (!verify.verify_message(hex_decode(msg), hex_decode(signature)))
		return 1;
	return 0;
}

size_t test_rsa()
{
	File rsa_enc = File("test_data/pubkey/rsaes.vec", "r");
	File rsa_sig = File("test_data/pubkey/rsa_sig.vec", "r");
	File rsa_verify = File("test_data/pubkey/rsa_verify.vec", "r");

	size_t fails = 0;

	fails += run_tests_bb(rsa_enc, "RSA Encryption", "Ciphertext", true,
						 (string[string] m)
						 {
						 	return rsaes_kat(m["E"], m["P"], m["Q"], m["Msg"],
												m["Padding"], m["Nonce"], m["Ciphertext"]);
						 });

	fails += run_tests_bb(rsa_sig, "RSA Signature", "Signature", true,
						 (string[string] m)
						 {
						 	return rsa_sig_kat(m["E"], m["P"], m["Q"], m["Msg"],
												  m["Padding"], m["Nonce"], m["Signature"]);
						 });

	fails += run_tests_bb(rsa_verify, "RSA Verify", "Signature", true,
						 (string[string] m)
						 {
						 	return rsa_sig_verify(m["E"], m["N"], m["Msg"],
													  m["Padding"], m["Signature"]);
						 });

	return fails;
}

