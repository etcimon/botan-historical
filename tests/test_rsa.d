#include "tests.h"
#include "test_pubkey.h"

#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/hex.h>
#include <iostream>
#include <fstream>

using namespace Botan;

namespace {

size_t rsaes_kat(string e,
					  string p,
					  string q,
					  string msg,
					  string padding,
					  string nonce,
					  string output)
{
	AutoSeeded_RNG rng;

	RSA_PrivateKey privkey(rng, BigInt(p), BigInt(q), BigInt(e));

	RSA_PublicKey pubkey = privkey;

	if(padding == "")
		padding = "Raw";

	PK_Encryptor_EME enc(pubkey, padding);
	PK_Decryptor_EME dec(privkey, padding);

	return validate_encryption(enc, dec, "RSAES/" + padding, msg, nonce, output);
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

	RSA_PrivateKey privkey(rng, BigInt(p), BigInt(q), BigInt(e));

	RSA_PublicKey pubkey = privkey;

	if(padding == "")
		padding = "Raw";

	PK_Verifier verify(pubkey, padding);
	PK_Signer sign(privkey, padding);

	return validate_signature(verify, sign, "RSA/" + padding, msg, rng, nonce, output);
}

size_t rsa_sig_verify(string e,
							 string n,
							 string msg,
							 string padding,
							 string signature)
{
	AutoSeeded_RNG rng;

	BigInt e_bn(e);
	BigInt n_bn(n);

	RSA_PublicKey key(n_bn, e_bn);

	if(padding == "")
		padding = "Raw";

	PK_Verifier verify(key, padding);

	if(!verify.verify_message(hex_decode(msg), hex_decode(signature)))
		return 1;
	return 0;
}

}

size_t test_rsa()
{
	File rsa_enc(PK_TEST_DATA_DIR "/rsaes.vec");
	File rsa_sig(PK_TEST_DATA_DIR "/rsa_sig.vec");
	File rsa_verify(PK_TEST_DATA_DIR "/rsa_verify.vec");

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

