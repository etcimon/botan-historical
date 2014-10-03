/*
* Policies for TLS
* (C) 2004-2010,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.tls_policy;
import botan.tls_ciphersuite;
import botan.tls_magic;
import botan.tls_exceptn;
import botan.internal.stl_util;
namespace TLS {

Vector!string Policy::allowed_ciphers() const
{
	return Vector!string({
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
	});
}

Vector!string Policy::allowed_signature_hashes() const
{
	return Vector!string({
		"SHA-512",
		"SHA-384",
		"SHA-256",
		"SHA-224",
		//"SHA-1",
		//"MD5",
	});
}

Vector!string Policy::allowed_macs() const
{
	return Vector!string({
		"AEAD",
		"SHA-384",
		"SHA-256",
		"SHA-1",
		//"MD5",
	});
}

Vector!string Policy::allowed_key_exchange_methods() const
{
	return Vector!string({
		"SRP_SHA",
		//"ECDHE_PSK",
		//"DHE_PSK",
		//"PSK",
		"ECDH",
		"DH",
		"RSA",
	});
}

Vector!string Policy::allowed_signature_methods() const
{
	return Vector!string({
		"ECDSA",
		"RSA",
		"DSA",
		//""
	});
}

Vector!string Policy::allowed_ecc_curves() const
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
string Policy::choose_curve(in Vector!string curve_names) const
{
	const Vector!string our_curves = allowed_ecc_curves();

	for (size_t i = 0; i != our_curves.size(); ++i)
		if (value_exists(curve_names, our_curves[i]))
			return our_curves[i];

	return ""; // no shared curve
}

DL_Group Policy::dh_group() const
{
	return DL_Group("modp/ietf/2048");
}

size_t Policy::minimum_dh_group_size() const
{
	return 1024;
}

/*
* Return allowed compression algorithms
*/
Vector!( byte ) Policy::compression() const
{
	return Vector!( byte ){ NO_COMPRESSION };
}

uint Policy::session_ticket_lifetime() const
{
	return 86400; // 1 day
}

bool Policy::acceptable_protocol_version(Protocol_Version _version) const
{
	// By default require TLS to minimize surprise
	if (_version.is_datagram_protocol())
		return false;

	return (_version > Protocol_Version::SSL_V3);
}

bool Policy::acceptable_ciphersuite(in Ciphersuite) const
{
	return true;
}

bool Policy::negotiate_heartbeat_support() const
{
	return false;
}

bool Policy::allow_server_initiated_renegotiation() const
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

		bool operator()(in Ciphersuite a, const Ciphersuite& b) const
		{
			if (a.kex_algo() != b.kex_algo())
			{
				for (size_t i = 0; i != m_kex.size(); ++i)
				{
					if (a.kex_algo() == m_kex[i])
						return true;
					if (b.kex_algo() == m_kex[i])
						return false;
				}
			}

			if (a.cipher_algo() != b.cipher_algo())
			{
				for (size_t i = 0; i != m_ciphers.size(); ++i)
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
				for (size_t i = 0; i != m_sigs.size(); ++i)
				{
					if (a.sig_algo() == m_sigs[i])
						return true;
					if (b.sig_algo() == m_sigs[i])
						return false;
				}
			}

			if (a.mac_algo() != b.mac_algo())
			{
				for (size_t i = 0; i != m_macs.size(); ++i)
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

Vector!( ushort ) Policy::ciphersuite_list(Protocol_Version _version,
															bool have_srp) const
{
	const Vector!string ciphers = allowed_ciphers();
	const Vector!string macs = allowed_macs();
	const Vector!string kex = allowed_key_exchange_methods();
	const Vector!string sigs = allowed_signature_methods();

	Ciphersuite_Preference_Ordering order(ciphers, macs, kex, sigs);

	std::set<Ciphersuite, Ciphersuite_Preference_Ordering> ciphersuites(order);

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
		throw new std::logic_error("Policy does not allow any available cipher suite");

	Vector!( ushort ) ciphersuite_codes;
	foreach (i; ciphersuites)
		ciphersuite_codes.push_back(i.ciphersuite_code());
	return ciphersuite_codes;
}

}

}
