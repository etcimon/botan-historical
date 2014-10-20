/*
* Hooks for application level policies on TLS connections
* (C) 2004-2006,2013 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.tls.tls_version;
import botan.tls_ciphersuite;
import botan.cert.x509.x509cert;
import botan.pubkey.algo.dl_group;
import botan.tls_ciphersuite;
import botan.tls_magic;
import botan.tls_exceptn;
import botan.internal.stl_util;
import vector;

/**
* TLS Policy Base Class
* Inherit and overload as desired to suit local policy concerns
*/
class Policy
{
public:

	/**
	* Returns a list of ciphers we are willing to negotiate, in
	* order of preference.
	*/
	Vector!string allowed_ciphers() const
	{
		return Vector!string([
			"AES-256/GCM",
			"AES-128/GCM",
			"AES-256/CCM",
			"AES-128/CCM",
			"AES-256/CCM-8",
			"AES-128/CCM-8",
			//"Camellia-256/GCM",
			//"Camellia-128/GCM",
			"AES-256",
			"AES-128",
			//"Camellia-256",
			//"Camellia-128",
			//"SEED"
			//"3DES",
			//"RC4",
		]);
	}

	/**
	* Returns a list of hash algorithms we are willing to use for
	* signatures, in order of preference.
	*/
	Vector!string allowed_signature_hashes() const
	{
		return Vector!string([
			"SHA-512",
			"SHA-384",
			"SHA-256",
			"SHA-224",
			//"SHA-1",
			//"MD5",
		]);
	}


	/**
	* Returns a list of MAC algorithms we are willing to use.
	*/
	Vector!string allowed_macs() const
	{
		return Vector!string([
			"AEAD",
			"SHA-384",
			"SHA-256",
			"SHA-1",
			//"MD5",
		]);
	}

	/**
	* Returns a list of key exchange algorithms we are willing to
	* use, in order of preference. Allowed values: DH, empty string
	* (representing RSA using server certificate key)
	*/
	Vector!string allowed_key_exchange_methods() const
	{
		return Vector!string([
			"SRP_SHA",
			//"ECDHE_PSK",
			//"DHE_PSK",
			//"PSK",
			"ECDH",
			"DH",
			"RSA",
		]);
	}

	/**
	* Returns a list of signature algorithms we are willing to
	* use, in order of preference. Allowed values RSA and DSA.
	*/
	Vector!string allowed_signature_methods() const
	{
		return Vector!string([
			"ECDSA",
			"RSA",
			"DSA",
			//""
		]);
	}

	/**
	* Return list of ECC curves we are willing to use in order of preference
	*/
	abstract Vector!string allowed_ecc_curves() const;

	/**
	* Returns a list of compression algorithms we are willing to use,
	* in order of preference. Allowed values any value of
	* Compression_Method.
	*
	* @note Compression is not currently supported
	*/
	abstract Vector!ubyte compression() const;

	/**
	* Choose an elliptic curve to use
	*/
	abstract string choose_curve(in Vector!string curve_names) const;

	/**
	* Attempt to negotiate the use of the heartbeat extension
	*/
	abstract bool negotiate_heartbeat_support() const;

	/**
	* Allow renegotiation even if the counterparty doesn't
	* support the secure renegotiation extension.
	*
	* @warning Changing this to true exposes you to injected
	* plaintext attacks. Read RFC 5746 for background.
	*/
	abstract bool allow_insecure_renegotiation() const { return false; }

	/**
	* Allow servers to initiate a new handshake
	*/
	abstract bool allow_server_initiated_renegotiation() const;

	/**
	* Return the group to use for ephemeral Diffie-Hellman key agreement
	*/
	abstract DL_Group dh_group() const;

	/**
	* Return the minimum DH group size we're willing to use
	*/
	abstract size_t minimum_dh_group_size() const;

	/**
	* If this function returns false, unknown SRP/PSK identifiers
	* will be rejected with an unknown_psk_identifier alert as soon
	* as the non-existence is identified. Otherwise, a false
	* identifier value will be used and the protocol allowed to
	* proceed, causing the handshake to eventually fail without
	* revealing that the username does not exist on this system.
	*/
	abstract bool hide_unknown_users() const { return false; }

	/**
	* Return the allowed lifetime of a session ticket. If 0, session
	* tickets do not expire until the session ticket key rolls over.
	* Expired session tickets cannot be used to resume a session.
	*/
	abstract uint session_ticket_lifetime() const;

	/**
	* @return true if and only if we are willing to accept this version
	* Default accepts only TLS, so if you want to enable DTLS override
	* in your application.
	*/
	abstract bool acceptable_protocol_version(Protocol_Version _version) const;

	abstract bool acceptable_ciphersuite(in Ciphersuite suite) const;

	/**
	* @return true if servers should choose the ciphersuite matching
	*			their highest preference, rather than the clients.
	*			Has no effect on client side.
	*/
	abstract bool server_uses_own_ciphersuite_preferences() const { return true; }

	/**
	* Return allowed ciphersuites, in order of preference
	*/
	abstract Vector!( ushort ) ciphersuite_list(Protocol_Version _version,
																bool have_srp) const;

	~this() {}
};

/**
* NSA Suite B 128-bit security level (see @rfc 6460)
*/
class NSA_Suite_B_128 : Policy
{
public:
	override Vector!string allowed_ciphers() const
	{ return Vector!string(["AES-128/GCM"]); }

	override Vector!string allowed_signature_hashes() const
	{ return Vector!string(["SHA-256"]); }

	override Vector!string allowed_macs() const
	{ return Vector!string(["AEAD"]); }

	override Vector!string allowed_key_exchange_methods() const
	{ return Vector!string(["ECDH"]); }

	override Vector!string allowed_signature_methods() const
	{ return Vector!string(["ECDSA"]); }

	override Vector!string allowed_ecc_curves() const
	{ return Vector!string(["secp256r1"]); }

	override bool acceptable_protocol_version(Protocol_Version _version) const
	{ return _version == Protocol_Version.TLS_V12; }
};

/**
* Policy for DTLS. We require DTLS v1.2 and an AEAD mode
*/
class Datagram_Policy : Policy
{
public:
	override Vector!string allowed_macs() const
	{ return Vector!string(["AEAD"]); }

	override bool acceptable_protocol_version(Protocol_Version _version) const
	{ return _version == Protocol_Version.DTLS_V12; }
};











Vector!string allowed_ecc_curves() const
{
	return Vector!string({
		"brainpool512r1",
			"brainpool384r1",
			"brainpool256r1",
			"secp521r1",
			"secp384r1",
			"secp256r1",
			"secp256k1",
			"secp224r1",
			"secp224k1",
			//"secp192r1",
			//"secp192k1",
			//"secp160r2",
			//"secp160r1",
			//"secp160k1",
	});
}

/*
* Choose an ECC curve to use
*/
string choose_curve(in Vector!string curve_names) const
{
	const Vector!string our_curves = allowed_ecc_curves();
	
	for (size_t i = 0; i != our_curves.length; ++i)
		if (value_exists(curve_names, our_curves[i]))
			return our_curves[i];
	
	return ""; // no shared curve
}

DL_Group dh_group() const
{
	return DL_Group("modp/ietf/2048");
}

size_t minimum_dh_group_size() const
{
	return 1024;
}

/*
* Return allowed compression algorithms
*/
Vector!ubyte compression() const
{
	return Vector!ubyte{ NO_COMPRESSION };
}

Duration session_ticket_lifetime() const
{
	return TickDuration.from!"seconds"(86400).to!Duration; // 1 day
}

bool acceptable_protocol_version(Protocol_Version _version) const
{
	// By default require TLS to minimize surprise
	if (_version.is_datagram_protocol())
		return false;
	
	return (_version > Protocol_Version.SSL_V3);
}

bool acceptable_ciphersuite(in Ciphersuite) const
{
	return true;
}

bool negotiate_heartbeat_support() const
{
	return false;
}

bool allow_server_initiated_renegotiation() const
{
	return true;
}

namespace {
	
	class Ciphersuite_Preference_Ordering
	{
	public:
		Ciphersuite_Preference_Ordering(in Vector!string ciphers,
		                                const Vector!string& macs,
		                                const Vector!string& kex,
		                                const Vector!string& sigs) :
		m_ciphers(ciphers), m_macs(macs), m_kex(kex), m_sigs(sigs) {}
		
		bool opCall(in Ciphersuite a, const Ciphersuite& b) const
		{
			if (a.kex_algo() != b.kex_algo())
			{
				for (size_t i = 0; i != m_kex.length; ++i)
				{
					if (a.kex_algo() == m_kex[i])
						return true;
					if (b.kex_algo() == m_kex[i])
						return false;
				}
			}
			
			if (a.cipher_algo() != b.cipher_algo())
			{
				for (size_t i = 0; i != m_ciphers.length; ++i)
				{
					if (a.cipher_algo() == m_ciphers[i])
						return true;
					if (b.cipher_algo() == m_ciphers[i])
						return false;
				}
			}
			
			if (a.cipher_keylen() != b.cipher_keylen())
			{
				if (a.cipher_keylen() < b.cipher_keylen())
					return false;
				if (a.cipher_keylen() > b.cipher_keylen())
					return true;
			}
			
			if (a.sig_algo() != b.sig_algo())
			{
				for (size_t i = 0; i != m_sigs.length; ++i)
				{
					if (a.sig_algo() == m_sigs[i])
						return true;
					if (b.sig_algo() == m_sigs[i])
						return false;
				}
			}
			
			if (a.mac_algo() != b.mac_algo())
			{
				for (size_t i = 0; i != m_macs.length; ++i)
				{
					if (a.mac_algo() == m_macs[i])
						return true;
					if (b.mac_algo() == m_macs[i])
						return false;
				}
			}
			
			return false; // equal (?!?)
		}
	private:
		Vector!string m_ciphers, m_macs, m_kex, m_sigs;
	};
	
}

Vector!( ushort ) ciphersuite_list(Protocol_Version _version,
                                           bool have_srp) const
{
	const Vector!string ciphers = allowed_ciphers();
	const Vector!string macs = allowed_macs();
	const Vector!string kex = allowed_key_exchange_methods();
	const Vector!string sigs = allowed_signature_methods();
	
	Ciphersuite_Preference_Ordering order(ciphers, macs, kex, sigs);
	
	Set<Ciphersuite, Ciphersuite_Preference_Ordering> ciphersuites(order);
	
	foreach (suite; Ciphersuite::all_known_ciphersuites())
	{
		if (!acceptable_ciphersuite(suite))
			continue;
		
		if (!have_srp && suite.kex_algo() == "SRP_SHA")
			continue;
		
		if (_version.is_datagram_protocol() && suite.cipher_algo() == "RC4")
			continue;
		
		if (!_version.supports_aead_modes() && suite.mac_algo() == "AEAD")
			continue;
		
		if (!value_exists(kex, suite.kex_algo()))
			continue; // unsupported key exchange
		
		if (!value_exists(ciphers, suite.cipher_algo()))
			continue; // unsupported cipher
		
		if (!value_exists(macs, suite.mac_algo()))
			continue; // unsupported MAC algo
		
		if (!value_exists(sigs, suite.sig_algo()))
		{
			// allow if it's an empty sig algo and we want to use PSK
			if (suite.sig_algo() != "" || !suite.psk_ciphersuite())
				continue;
		}
		
		// OK, allow it:
		ciphersuites.insert(suite);
	}
	
	if (ciphersuites.empty())
		throw new Logic_Error("Policy does not allow any available cipher suite");
	
	Vector!( ushort ) ciphersuite_codes;
	foreach (i; ciphersuites)
		ciphersuite_codes.push_back(i.ciphersuite_code());
	return ciphersuite_codes;
}

}