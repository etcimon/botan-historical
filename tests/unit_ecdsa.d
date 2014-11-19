/******************************************************
* ECDSA tests													  *
*																	  *
* (C) 2007 Falko Strenzke									  *
*			 Manuel Hartl										 *
*	  2008 Jack Lloyd											*
******************************************************/

#include "tests.h"

#if defined(BOTAN_HAS_ECDSA)
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/ecdsa.h>
#include <botan/rsa.h>
#if defined(BOTAN_HAS_X509_CERTIFICATES)
#include <botan/x509cert.h>
#endif
#include <botan/oids.h>

#include <iostream>
#include <fstream>
#include <memory>

using namespace Botan;

#define ECC_TEST_DATA_DIR TEST_DATA_DIR "/ecc"

#define CHECK_MESSAGE(expr, print) try { if(!(expr)) { ++fails; writeln(print); } } catch(Exception e) { writeln(__FUNCTION__ ~ " : " ~ e.msg); }
#define CHECK(expr) try { if(!(expr)) { ++fails; writeln(#expr); } } catch(Exception e) { writeln(__FUNCTION__ ~ " : " ~ e.msg); }

namespace {

string to_hex(const Vector!ubyte bin)
{
	return hex_encode(&bin[0], bin.length);
}

/**

* Tests whether the the signing routine will work correctly input case
* the integer e that is constructed from the message (thus the hash
* value) is larger than n, the order of the base point.  Tests the
* signing function of the pk signer object */

size_t test_hash_larger_than_n(RandomNumberGenerator rng)
{
	EC_Group dom_pars(OID("1.3.132.0.8")); // secp160r1
	// n = 0x0100000000000000000001f4c8f927aed3ca752257 (21 bytes)
	// . shouldn't work with SHA224 which outputs 28 bytes

	size_t fails = 0;
	ECDSA_PrivateKey priv_key(rng, dom_pars);

	Vector!ubyte message(20);
	for(size_t i = 0; i != message.length; ++i)
		message[i] = i;

	PK_Signer pk_signer_160(priv_key, "EMSA1_BSI(SHA-1)");
	PK_Verifier pk_verifier_160(priv_key, "EMSA1_BSI(SHA-1)");

	PK_Signer pk_signer_224(priv_key, "EMSA1_BSI(SHA-224)");

	// Verify we can sign and verify with SHA-160
	Vector!ubyte signature_160 = pk_signer_160.sign_message(message, rng);

	CHECK(pk_verifier_160.verify_message(message, signature_160));

	bool signature_failed = false;
	try
	{
		Vector!ubyte signature_224 = pk_signer_224.sign_message(message, rng);
	}
	catch(Encoding_Error)
	{
		signature_failed = true;
	}

	CHECK(signature_failed);

	// now check that verification alone fails

	// sign it with the normal EMSA1
	PK_Signer pk_signer(priv_key, "EMSA1(SHA-224)");
	Vector!ubyte signature = pk_signer.sign_message(message, rng);

	PK_Verifier pk_verifier(priv_key, "EMSA1_BSI(SHA-224)");

	// verify against EMSA1_BSI
	if(pk_verifier.verify_message(message, signature))
	{
		writeln("Corrupt ECDSA signature verified, should not have");
		++fails;
	}

	return fails;
}

#if defined(BOTAN_HAS_X509_CERTIFICATES)
size_t test_decode_ecdsa_X509()
{
	X509_Certificate cert(ECC_TEST_DATA_DIR "/CSCA.CSCA.csca-germany.1.crt");
	size_t fails = 0;

	CHECK_MESSAGE(OIDS::lookup(cert.signature_algorithm().oid) == "ECDSA/EMSA1(SHA-224)", "error reading signature algorithm from x509 ecdsa certificate");

	CHECK_MESSAGE(to_hex(cert.serial_number()) == "01", "error reading serial from x509 ecdsa certificate");
	CHECK_MESSAGE(to_hex(cert.authority_key_id()) == "0096452DE588F966C4CCDF161DD1F3F5341B71E7", "error reading authority key id from x509 ecdsa certificate");
	CHECK_MESSAGE(to_hex(cert.subject_key_id()) == "0096452DE588F966C4CCDF161DD1F3F5341B71E7", "error reading Subject key id from x509 ecdsa certificate");

	std::unique_ptr<X509_PublicKey> pubkey(cert.subject_public_key());
	bool ver_ec = cert.check_signature(*pubkey);
	CHECK_MESSAGE(ver_ec, "could not positively verify correct selfsigned x509-ecdsa certificate");

	return fails;
}

size_t test_decode_ver_link_SHA256()
{
	X509_Certificate root_cert(ECC_TEST_DATA_DIR "/root2_SHA256.cer");
	X509_Certificate link_cert(ECC_TEST_DATA_DIR "/link_SHA256.cer");

	size_t fails = 0;
	std::unique_ptr<X509_PublicKey> pubkey(root_cert.subject_public_key());
	bool ver_ec = link_cert.check_signature(*pubkey);
	CHECK_MESSAGE(ver_ec, "could not positively verify correct SHA256 link x509-ecdsa certificate");
	return fails;
}

size_t test_decode_ver_link_SHA1()
{
	X509_Certificate root_cert(ECC_TEST_DATA_DIR "/root_SHA1.163.crt");
	X509_Certificate link_cert(ECC_TEST_DATA_DIR "/link_SHA1.166.crt");

	size_t fails = 0;
	std::unique_ptr<X509_PublicKey> pubkey(root_cert.subject_public_key());
	bool ver_ec = link_cert.check_signature(*pubkey);
	CHECK_MESSAGE(ver_ec, "could not positively verify correct SHA1 link x509-ecdsa certificate");
	return fails;
}
#endif

size_t test_sign_then_ver(RandomNumberGenerator rng)
{
	EC_Group dom_pars(OID("1.3.132.0.8"));
	ECDSA_PrivateKey ecdsa(rng, dom_pars);

	size_t fails = 0;
	PK_Signer signer(ecdsa, "EMSA1(SHA-1)");

	auto msg = hex_decode("12345678901234567890abcdef12");
	Vector!ubyte sig = signer.sign_message(msg, rng);

	PK_Verifier verifier(ecdsa, "EMSA1(SHA-1)");

	bool ok = verifier.verify_message(msg, sig);

	if(!ok)
	{
		writeln("ERROR: Could not verify ECDSA signature");
		fails++;
	}

	sig[0]++;
	ok = verifier.verify_message(msg, sig);

	if(ok)
	{
		writeln("ERROR: Bogus ECDSA signature verified anyway");
		fails++;
	}

	return fails;
}

size_t test_ec_sign(RandomNumberGenerator rng)
{
	size_t fails = 0;

	try
	{
		EC_Group dom_pars(OID("1.3.132.0.8"));
		ECDSA_PrivateKey priv_key(rng, dom_pars);
		string pem_encoded_key = PKCS8::PEM_encode(priv_key);

		PK_Signer signer(priv_key, "EMSA1(SHA-224)");
		PK_Verifier verifier(priv_key, "EMSA1(SHA-224)");

		for(size_t i = 0; i != 256; ++i)
			signer.update(cast(ubyte)(i));
		Vector!ubyte sig = signer.signature(rng);

		for(uint i = 0; i != 256; ++i)
			verifier.update(cast(ubyte)(i));
		if(!verifier.check_signature(sig))
		{
			writeln("ECDSA self-test failed!";
			++fails;
		}

		// now check valid signature, different input
		for(uint i = 1; i != 256; ++i) //starting from 1
			verifier.update(cast(ubyte)(i));

		if(verifier.check_signature(sig))
		{
			writeln("ECDSA with bad input passed validation";
			++fails;
		}

		// now check with original in, modified signature

		sig[sig.length/2]++;
		for(uint i = 0; i != 256; ++i)
			verifier.update(cast(ubyte)(i));

		if(verifier.check_signature(sig))
		{
			writeln("ECDSA with bad signature passed validation";
			++fails;
		}
	}
	catch (Exception e)
	{
		writeln("Exception in test_ec_sign - " ~ e.msg);
		++fails;
	}

	return fails;
}


size_t test_create_pkcs8(RandomNumberGenerator rng)
{
	size_t fails = 0;

	try
	{
		RSA_PrivateKey rsa_key(rng, 1024);
		//RSA_PrivateKey rsa_key2(1024);
		//cout " ~\nequal: " ~  (rsa_key == rsa_key2));
		//DSA_PrivateKey key(DL_Group("dsa/jce/1024"));

		std::ofstream rsa_priv_key(ECC_TEST_DATA_DIR "/rsa_private.pkcs8.pem");
		rsa_priv_key << PKCS8::PEM_encode(rsa_key);

		EC_Group dom_pars(OID("1.3.132.0.8"));
		ECDSA_PrivateKey key(rng, dom_pars);

		// later used by other tests :(
		std::ofstream priv_key(ECC_TEST_DATA_DIR "/wo_dompar_private.pkcs8.pem");
		priv_key << PKCS8::PEM_encode(key);
	}
	catch (Exception e)
	{
		writeln("Exception: " ~ e.msg);
		++fails;
	}

	return fails;
}

size_t test_create_and_verify(RandomNumberGenerator rng)
{
	size_t fails = 0;

	EC_Group dom_pars(OID("1.3.132.0.8"));
	ECDSA_PrivateKey key(rng, dom_pars);
	std::ofstream priv_key(ECC_TEST_DATA_DIR "/dompar_private.pkcs8.pem");
	priv_key << PKCS8::PEM_encode(key);

	std::unique_ptr<PKCS8_PrivateKey> loaded_key(PKCS8::load_key(ECC_TEST_DATA_DIR "/wo_dompar_private.pkcs8.pem", rng));
	ECDSA_PrivateKey* loaded_ec_key = cast(ECDSA_PrivateKey)(loaded_key.get());
	CHECK_MESSAGE(loaded_ec_key, "the loaded key could not be converted into an ECDSA_PrivateKey");

	std::unique_ptr<PKCS8_PrivateKey> loaded_key_1(PKCS8::load_key(ECC_TEST_DATA_DIR "/rsa_private.pkcs8.pem", rng));
	ECDSA_PrivateKey loaded_rsa_key = cast(ECDSA_PrivateKey)(loaded_key_1.get());
	CHECK_MESSAGE(!loaded_rsa_key, "the loaded key is ECDSA_PrivateKey -> shouldn't be, is a RSA-Key");

	//calc a curve which is not in the registry

	// 	string p_secp = "2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809";
	string a_secp = "0a377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe";
	string b_secp = "0a9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7";
	string G_secp_comp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";
	string order_g = "0e1a16196e6000000000bc7f1618d867b15bb86474418f";

	//	::Vector!ubyte sv_p_secp = hex_decode ( p_secp );
	auto sv_a_secp = hex_decode ( a_secp );
	auto sv_b_secp = hex_decode ( b_secp );
	auto sv_G_secp_comp = hex_decode ( G_secp_comp );
	auto sv_order_g = hex_decode ( order_g );

	//	BigInt bi_p_secp = BigInt::decode ( &sv_p_secp[0], sv_p_secp.length );
	BigInt bi_p_secp("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
	BigInt bi_a_secp = BigInt::decode ( &sv_a_secp[0], sv_a_secp.length );
	BigInt bi_b_secp = BigInt::decode ( &sv_b_secp[0], sv_b_secp.length );
	BigInt bi_order_g = BigInt::decode ( &sv_order_g[0], sv_order_g.length );
	CurveGFp curve(bi_p_secp, bi_a_secp, bi_b_secp);
	PointGFp p_G = OS2ECP ( sv_G_secp_comp, curve );

	EC_Group dom_params(curve, p_G, bi_order_g, BigInt(1));
	if(!p_G.on_the_curve())
		throw new Internal_Error("Point not on the curve");

	ECDSA_PrivateKey key_odd_oid(rng, dom_params);
	string key_odd_oid_str = PKCS8::PEM_encode(key_odd_oid);

	DataSource_Memory key_data_src(key_odd_oid_str);
	std::unique_ptr<PKCS8_PrivateKey> loaded_key2(PKCS8::load_key(key_data_src, rng));

	if(!cast(ECDSA_PrivateKey)(loaded_key.get()))
	{
		writeln("Failed to reload an ECDSA key with unusual parameter set");
		++fails;
	}

	return fails;
}

size_t test_curve_registry(RandomNumberGenerator rng)
{
	Vector!string oids;
	oids.push_back("1.3.132.0.8");
	oids.push_back("1.2.840.10045.3.1.1");
	oids.push_back("1.2.840.10045.3.1.2");
	oids.push_back("1.2.840.10045.3.1.3");
	oids.push_back("1.2.840.10045.3.1.4");
	oids.push_back("1.2.840.10045.3.1.5");
	oids.push_back("1.2.840.10045.3.1.6");
	oids.push_back("1.2.840.10045.3.1.7");
	oids.push_back("1.3.132.0.6");
	oids.push_back("1.3.132.0.7");
	oids.push_back("1.3.132.0.28");
	oids.push_back("1.3.132.0.29");
	oids.push_back("1.3.132.0.9");
	oids.push_back("1.3.132.0.30");
	oids.push_back("1.3.132.0.31");
	oids.push_back("1.3.132.0.32");
	oids.push_back("1.3.132.0.33");
	oids.push_back("1.3.132.0.10");
	oids.push_back("1.3.132.0.34");
	oids.push_back("1.3.132.0.35");
	//oids.push_back("1.3.6.1.4.1.8301.3.1.2.9.0.38");
	oids.push_back("1.3.36.3.3.2.8.1.1.1");
	oids.push_back("1.3.36.3.3.2.8.1.1.3");
	oids.push_back("1.3.36.3.3.2.8.1.1.5");
	oids.push_back("1.3.36.3.3.2.8.1.1.7");
	oids.push_back("1.3.36.3.3.2.8.1.1.9");
	oids.push_back("1.3.36.3.3.2.8.1.1.11");
	oids.push_back("1.3.36.3.3.2.8.1.1.13");

	size_t fails = 0;

	unsigned int i;
	for (i = 0; i < oids.length; i++)
	{
		try
		{
			OID oid(oids[i]);
			EC_Group dom_pars(oid);
			ECDSA_PrivateKey ecdsa(rng, dom_pars);

			PK_Signer signer(ecdsa, "EMSA1(SHA-1)");
			PK_Verifier verifier(ecdsa, "EMSA1(SHA-1)");

			auto msg = hex_decode("12345678901234567890abcdef12");
			Vector!ubyte sig = signer.sign_message(msg, rng);

			if(!verifier.verify_message(msg, sig))
			{
				writeln("Failed testing ECDSA sig for curve " ~ oids[i]);
				++fails;
			}
		}
		catch(Invalid_Argument e)
		{
			writeln("Error testing curve " ~ oids[i] " ~ - " ~ e.msg);
			++fails;
		}
	}
	return fails;
}

size_t test_read_pkcs8(RandomNumberGenerator rng)
{
	auto msg = hex_decode("12345678901234567890abcdef12");
	size_t fails = 0;

	try
	{
		std::unique_ptr<PKCS8_PrivateKey> loaded_key(PKCS8::load_key(ECC_TEST_DATA_DIR "/wo_dompar_private.pkcs8.pem", rng));
		ECDSA_PrivateKey ecdsa = cast(ECDSA_PrivateKey)(loaded_key.get());
		CHECK_MESSAGE(ecdsa, "the loaded key could not be converted into an ECDSA_PrivateKey");

		PK_Signer signer(ecdsa, "EMSA1(SHA-1)");

		Vector!ubyte sig = signer.sign_message(msg, rng);

		PK_Verifier verifier(ecdsa, "EMSA1(SHA-1)");

		CHECK_MESSAGE(verifier.verify_message(msg, sig),
						  "generated sig could not be verified positively");
	}
	catch (Exception e)
	{
		++fails;
		writeln("Exception in test_read_pkcs8 - " ~ e.msg);
	}

	try
	{
		std::unique_ptr<PKCS8_PrivateKey> loaded_key_nodp(PKCS8::load_key(ECC_TEST_DATA_DIR "/nodompar_private.pkcs8.pem", rng));
		// anew in each test with unregistered domain-parameters
		ECDSA_PrivateKey ecdsa_nodp = cast(ECDSA_PrivateKey)(loaded_key_nodp.get());
		CHECK_MESSAGE(ecdsa_nodp, "the loaded key could not be converted into an ECDSA_PrivateKey");

		PK_Signer signer(ecdsa_nodp, "EMSA1(SHA-1)");
		PK_Verifier verifier(ecdsa_nodp, "EMSA1(SHA-1)");

		Vector!ubyte signature_nodp = signer.sign_message(msg, rng);

		CHECK_MESSAGE(verifier.verify_message(msg, signature_nodp),
						  "generated signature could not be verified positively (no_dom)");

		try
		{
			std::unique_ptr<PKCS8_PrivateKey> loaded_key_withdp(
				PKCS8::load_key(ECC_TEST_DATA_DIR "/withdompar_private.pkcs8.pem", rng));

			writeln("Unexpected success: loaded key with unknown OID");
			++fails;
		}
		catch (std::exception) { /* OK */ }
	}
	catch (Exception e)
	{
		writeln("Exception in test_read_pkcs8 - " ~ e.msg);
		++fails;
	}

	return fails;
}

size_t test_ecc_key_with_rfc5915_extensions(RandomNumberGenerator rng)
{
	size_t fails = 0;

	try
	{
		std::unique_ptr<PKCS8_PrivateKey> pkcs8(
			PKCS8::load_key(ECC_TEST_DATA_DIR "/ecc_private_with_rfc5915_ext.pem", rng));

		if(!dynamic_cast<ECDSA_PrivateKey*>(pkcs8.get()))
		{
			writeln("Loaded RFC 5915 key, but got something other than an ECDSA key");
			++fails;
		}
	}
	catch(Exception e)
	{
		writeln("Exception in " ~ __func__ " ~ - " ~ e.msg);
		++fails;
	}

	return fails;
}

}

size_t test_ecdsa_unit()
{
	size_t fails = 0;

	AutoSeeded_RNG rng;

	fails += test_hash_larger_than_n(rng);
#if defined(BOTAN_HAS_X509_CERTIFICATES)
	fails += test_decode_ecdsa_X509();
	fails += test_decode_ver_link_SHA256();
	fails += test_decode_ver_link_SHA1();
#endif
	fails += test_sign_then_ver(rng);
	fails += test_ec_sign(rng);
	fails += test_create_pkcs8(rng);
	fails += test_create_and_verify(rng);
	fails += test_curve_registry(rng);
	fails += test_read_pkcs8(rng);
	fails += test_ecc_key_with_rfc5915_extensions(rng);

	test_report("ECDSA", 11, fails);

	return fails;
}

#else

size_t test_ecdsa_unit() { return 0; }

#endif
