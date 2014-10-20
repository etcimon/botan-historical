/*
* TLS Cipher Suite
* (C) 2004-2010,2012,2013 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.tls_ciphersuite;
import botan.libstate.libstate;
import botan.parsing;
import sstream;
import stdexcept;


namespace {

/*
* This way all work happens at the constuctor call, and we can
* rely on that happening only once in C++11.
*/
Vector!( Ciphersuite ) gather_known_ciphersuites()
{
	Vector!( Ciphersuite ) ciphersuites;

	for (size_t i = 0; i <= 0xFFFF; ++i)
	{
		Ciphersuite suite = Ciphersuite::by_id(i);

		if (suite.valid())
			ciphersuites.push_back(suite);
	}

	return ciphersuites;
}

}

const Vector!( Ciphersuite )& Ciphersuite::all_known_ciphersuites()
{
	static Vector!( Ciphersuite ) all_ciphersuites(gather_known_ciphersuites());
	return all_ciphersuites;
}

Ciphersuite Ciphersuite::by_name(in string name)
{
	foreach (suite; all_known_ciphersuites())
	{
		if (suite.to_string() == name)
			return suite;
	}

	return Ciphersuite(); // some unknown ciphersuite
}

Ciphersuite::Ciphersuite(ushort ciphersuite_code,
								 string sig_algo,
								 string kex_algo,
								 string cipher_algo,
								 size_t cipher_keylen,
								 size_t cipher_ivlen,
								 string mac_algo,
								 size_t mac_keylen,
								 string prf_algo) :
	m_ciphersuite_code(ciphersuite_code),
	m_sig_algo(sig_algo),
	m_kex_algo(kex_algo),
	m_cipher_algo(cipher_algo),
	m_mac_algo(mac_algo),
	m_prf_algo(prf_algo),
	m_cipher_keylen(cipher_keylen),
	m_cipher_ivlen(cipher_ivlen),
	m_mac_keylen(mac_keylen)
{
}

bool Ciphersuite::psk_ciphersuite() const
{
	return (kex_algo() == "PSK" ||
			  kex_algo() == "DHE_PSK" ||
			  kex_algo() == "ECDHE_PSK");
}

bool Ciphersuite::ecc_ciphersuite() const
{
	return (sig_algo() == "ECDSA" || kex_algo() == "ECDH" || kex_algo() == "ECDHE_PSK");
}

bool Ciphersuite::valid() const
{
	if (!m_cipher_keylen) // uninitialized object
		return false;

	AlgorithmFactory af = global_state().algorithm_factory();

	if (!af.prototype_hash_function(prf_algo()))
		return false;

	if (mac_algo() == "AEAD")
	{
		auto cipher_and_mode = splitter(cipher_algo(), '/');
		BOTAN_ASSERT(cipher_and_mode.length == 2, "Expected format for AEAD algo");
		if (!af.prototype_block_cipher(cipher_and_mode[0]))
			return false;

		const auto mode = cipher_and_mode[1];

#if !defined(BOTAN_HAS_AEAD_CCM)
		if (mode == "CCM" || mode == "CCM-8")
			return false;
#endif

#if !defined(BOTAN_HAS_AEAD_GCM)
		if (mode == "GCM")
			return false;
#endif

#if !defined(BOTAN_HAS_AEAD_OCB)
		if (mode == "OCB")
			return false;
#endif
	}
	else
	{
		if (!af.prototype_block_cipher(cipher_algo()) &&
			!af.prototype_stream_cipher(cipher_algo()))
			return false;

		if (!af.prototype_hash_function(mac_algo()))
			return false;
	}

	if (kex_algo() == "SRP_SHA")
	{
#if !defined(BOTAN_HAS_SRP6)
		return false;
#endif
	}
	else if (kex_algo() == "ECDH" || kex_algo() == "ECDHE_PSK")
	{
#if !defined(BOTAN_HAS_ECDH)
		return false;
#endif
	}
	else if (kex_algo() == "DH" || kex_algo() == "DHE_PSK")
	{
#if !defined(BOTAN_HAS_DIFFIE_HELLMAN)
		return false;
#endif
	}

	if (sig_algo() == "DSA")
	{
#if !defined(BOTAN_HAS_DSA)
		return false;
#endif
	}
	else if (sig_algo() == "ECDSA")
	{
#if !defined(BOTAN_HAS_ECDSA)
		return false;
#endif
	}
	else if (sig_algo() == "RSA")
	{
#if !defined(BOTAN_HAS_RSA)
		return false;
#endif
	}

	return true;
}

string Ciphersuite::to_string() const
{
	if (m_cipher_keylen == 0)
		throw new Exception("Ciphersuite::to_string - no value set");
	import std.array : Appender;
	Appender!string output;

	output ~= "TLS_";

	if (kex_algo() != "RSA")
	{
		if (kex_algo() == "DH")
			output ~= "DHE";
		else if (kex_algo() == "ECDH")
			output ~= "ECDHE";
		else
			output ~= kex_algo();

		output ~= '_';
	}

	if (sig_algo() == "DSA")
		output ~= "DSS_";
	else if (sig_algo() != "")
		output ~= sig_algo() ~ '_';

	output ~= "WITH_";

	if (cipher_algo() == "RC4")
	{
		output ~= "RC4_128_";
	}
	else
	{
		if (cipher_algo() == "3DES")
			output ~= "3DES_EDE";
		else if (cipher_algo().find("Camellia") == 0)
			output ~= "CAMELLIA_" ~ std.conv.to!string(8*cipher_keylen());
		else
			output ~= replace_chars(cipher_algo(), {'-', '/'}, '_');

		if (cipher_algo().find("/") != string::npos)
			output ~= "_"; // some explicit mode already included
		else
			output ~= "_CBC_";
	}

	if (mac_algo() == "SHA-1")
		output ~= "SHA";
	else if (mac_algo() == "AEAD")
		output ~= erase_chars(prf_algo(), {'-'});
	else
		output ~= erase_chars(mac_algo(), {'-'});

	return output.data;
}

}

}

