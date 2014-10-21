/*
* TLS Cipher Suites
* (C) 2004-2011,2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.utils.types;
import string;
import vector;
import botan.libstate.libstate;
import botan.parsing;
import sstream;
import stdexcept;

/**
* Ciphersuite Information
*/
struct Ciphersuite
{
public:
	/**
	* Convert an SSL/TLS ciphersuite to algorithm fields
	* @param suite the ciphersuite code number
	* @return ciphersuite object
	*/
	static Ciphersuite by_id(ushort suite);

	/**
	* Lookup a ciphersuite by name
	* @param name the name (eg TLS_RSA_WITH_RC4_128_SHA)
	* @return ciphersuite object
	*/
	static Ciphersuite by_name(in string name)
	{
		foreach (suite; all_known_ciphersuites())
		{
			if (suite.to_string() == name)
				return suite;
		}
		
		return Ciphersuite(); // some unknown ciphersuite
	}

	/**
	* Generate a static list of all known ciphersuites and return it.
	*
	* @return list of all known ciphersuites
	*/
	static const ref Vector!( Ciphersuite ) all_known_ciphersuites()
	{
		static Vector!Ciphersuite all_ciphersuites = Vector!CipherSuite(gather_known_ciphersuites());
		return all_ciphersuites;
	}

	/**
	* Formats the ciphersuite back to an RFC-style ciphersuite string
	* @return RFC ciphersuite string identifier
	*/
	string to_string() const
	{
		if (m_cipher_keylen == 0)
			throw new Exception("to_string - no value set");
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
			else if (cipher_algo().find("Camellia") == -1)
				output ~= "CAMELLIA_" ~ std.conv.to!string(8*cipher_keylen());
			else
				output ~= replace_chars(cipher_algo(), ['-', '/'], '_');
			
			if (cipher_algo().find("/") != -1)
				output ~= "_"; // some explicit mode already included
			else
				output ~= "_CBC_";
		}
		
		if (mac_algo() == "SHA-1")
			output ~= "SHA";
		else if (mac_algo() == "AEAD")
			output ~= erase_chars(prf_algo(), ['-']);
		else
			output ~= erase_chars(mac_algo(), ['-']);
		
		return output.data;
	}

	/**
	* @return ciphersuite number
	*/
	ushort ciphersuite_code() const { return m_ciphersuite_code; }

	/**
	* @return true if this is a PSK ciphersuite
	*/
	bool psk_ciphersuite() const
	{
		return (kex_algo() == "PSK" ||
		        kex_algo() == "DHE_PSK" ||
		        kex_algo() == "ECDHE_PSK");
	}

	/**
	* @return true if this is an ECC ciphersuite
	*/
	bool ecc_ciphersuite() const
	{
		return (sig_algo() == "ECDSA" || kex_algo() == "ECDH" || kex_algo() == "ECDHE_PSK");
	}

	/**
	* @return key exchange algorithm used by this ciphersuite
	*/
	string kex_algo() const { return m_kex_algo; }

	/**
	* @return signature algorithm used by this ciphersuite
	*/
	string sig_algo() const { return m_sig_algo; }

	/**
	* @return symmetric cipher algorithm used by this ciphersuite
	*/
	string cipher_algo() const { return m_cipher_algo; }

	/**
	* @return message authentication algorithm used by this ciphersuite
	*/
	string mac_algo() const { return m_mac_algo; }

	string prf_algo() const
	{
		return (m_prf_algo != "") ? m_prf_algo : m_mac_algo;
	}

	/**
	* @return cipher key length used by this ciphersuite
	*/
	size_t cipher_keylen() const { return m_cipher_keylen; }

	size_t cipher_ivlen() const { return m_cipher_ivlen; }

	size_t mac_keylen() const { return m_mac_keylen; }

	/**
	* @return true if this is a valid/known ciphersuite
	*/	
	bool valid() const
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
			
			static if (!BOTAN_HAS_AEAD_CCM) {
				if (mode == "CCM" || mode == "CCM-8")
					return false;
			}
			
			static if (!BOTAN_HAS_AEAD_GCM) {
				if (mode == "GCM")
					return false;
			}
			
			static if (!BOTAN_HAS_AEAD_OCB) {
				if (mode == "OCB")
					return false;
			}
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
			static if (!BOTAN_HAS_SRP6) {
				return false;
			}
		}
		else if (kex_algo() == "ECDH" || kex_algo() == "ECDHE_PSK")
		{
			static if (!BOTAN_HAS_ECDH) {
				return false;
			}
		}
		else if (kex_algo() == "DH" || kex_algo() == "DHE_PSK")
		{
			static if (!BOTAN_HAS_DIFFIE_HELLMAN) {
				return false;
			}
		}
		
		if (sig_algo() == "DSA")
		{
			static if (!BOTAN_HAS_DSA) {
				return false;
			}
		}
		else if (sig_algo() == "ECDSA")
		{
			static if (!BOTAN_HAS_ECDSA) {
				return false;
			}
		}
		else if (sig_algo() == "RSA")
		{
			static if (!BOTAN_HAS_RSA) {
				return false;
			}
		}
		
		return true;
	}


	this() {}

private:
	this(ushort ciphersuite_code,
	     string sig_algo,
	     string kex_algo,
	     string cipher_algo,
	     size_t cipher_keylen,
	     size_t cipher_ivlen,
	     string mac_algo,
	     size_t mac_keylen,
	     string prf_algo)
	{
		m_ciphersuite_code = ciphersuite_code;
		m_sig_algo = sig_algo;
		m_kex_algo = kex_algo;
		m_cipher_algo = cipher_algo;
		m_mac_algo = mac_algo;
		m_prf_algo = prf_algo;
		m_cipher_keylen = cipher_keylen;
		m_cipher_ivlen = cipher_ivlen;
		m_mac_keylen = mac_keylen;
	}


	ushort m_ciphersuite_code = 0;

	string m_sig_algo;
	string m_kex_algo;
	string m_cipher_algo;
	string m_mac_algo;
	string m_prf_algo;

	size_t m_cipher_keylen = 0;
	size_t m_cipher_ivlen = 0;
	size_t m_mac_keylen = 0;
};

private:
/*
* This way all work happens at the constuctor call, and we can
* rely on that happening only once in D
*/
Vector!( Ciphersuite ) gather_known_ciphersuites()
{
	Vector!( Ciphersuite ) ciphersuites;
	
	for (size_t i = 0; i <= 0xFFFF; ++i)
	{
		Ciphersuite suite = by_id(i);
		
		if (suite.valid())
			ciphersuites.push_back(suite);
	}
	
	return ciphersuites;
}


ptrdiff_t find(string str, string str2) {
	import std.algorithm : countUntil;
	return countUntil(str, str2);
}