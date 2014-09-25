/*
* Hooks for application level policies on TLS connections
* (C) 2004-2006,2013 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#ifndef BOTAN_TLS_POLICY_H__
#define BOTAN_TLS_POLICY_H__

#include <botan/tls_version.h>
#include <botan/tls_ciphersuite.h>
#include <botan/x509cert.h>
#include <botan/dl_group.h>
#include <vector>

namespace Botan {

namespace TLS {

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
		abstract std::vector<string> allowed_ciphers() const;

		/**
		* Returns a list of hash algorithms we are willing to use for
		* signatures, in order of preference.
		*/
		abstract std::vector<string> allowed_signature_hashes() const;

		/**
		* Returns a list of MAC algorithms we are willing to use.
		*/
		abstract std::vector<string> allowed_macs() const;

		/**
		* Returns a list of key exchange algorithms we are willing to
		* use, in order of preference. Allowed values: DH, empty string
		* (representing RSA using server certificate key)
		*/
		abstract std::vector<string> allowed_key_exchange_methods() const;

		/**
		* Returns a list of signature algorithms we are willing to
		* use, in order of preference. Allowed values RSA and DSA.
		*/
		abstract std::vector<string> allowed_signature_methods() const;

		/**
		* Return list of ECC curves we are willing to use in order of preference
		*/
		abstract std::vector<string> allowed_ecc_curves() const;

		/**
		* Returns a list of compression algorithms we are willing to use,
		* in order of preference. Allowed values any value of
		* Compression_Method.
		*
		* @note Compression is not currently supported
		*/
		abstract std::vector<byte> compression() const;

		/**
		* Choose an elliptic curve to use
		*/
		abstract string choose_curve(const std::vector<string>& curve_names) const;

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
		abstract u32bit session_ticket_lifetime() const;

		/**
		* @return true if and only if we are willing to accept this version
		* Default accepts only TLS, so override if you want to enable DTLS
		* in your application.
		*/
		abstract bool acceptable_protocol_version(Protocol_Version version) const;

		abstract bool acceptable_ciphersuite(const Ciphersuite& suite) const;

		/**
		* @return true if servers should choose the ciphersuite matching
		*			their highest preference, rather than the clients.
		*			Has no effect on client side.
		*/
		abstract bool server_uses_own_ciphersuite_preferences() const { return true; }

		/**
		* Return allowed ciphersuites, in order of preference
		*/
		abstract std::vector<u16bit> ciphersuite_list(Protocol_Version version,
																	bool have_srp) const;

		abstract ~Policy() {}
	};

/**
* NSA Suite B 128-bit security level (see @rfc 6460)
*/
class NSA_Suite_B_128 : public Policy
	{
	public:
		std::vector<string> allowed_ciphers() const override
			{ return std::vector<string>({"AES-128/GCM"}); }

		std::vector<string> allowed_signature_hashes() const override
			{ return std::vector<string>({"SHA-256"}); }

		std::vector<string> allowed_macs() const override
			{ return std::vector<string>({"AEAD"}); }

		std::vector<string> allowed_key_exchange_methods() const override
			{ return std::vector<string>({"ECDH"}); }

		std::vector<string> allowed_signature_methods() const override
			{ return std::vector<string>({"ECDSA"}); }

		std::vector<string> allowed_ecc_curves() const override
			{ return std::vector<string>({"secp256r1"}); }

		bool acceptable_protocol_version(Protocol_Version version) const override
			{ return version == Protocol_Version::TLS_V12; }
	};

/**
* Policy for DTLS. We require DTLS v1.2 and an AEAD mode
*/
class Datagram_Policy : public Policy
	{
	public:
		std::vector<string> allowed_macs() const override
			{ return std::vector<string>({"AEAD"}); }

		bool acceptable_protocol_version(Protocol_Version version) const override
			{ return version == Protocol_Version::DTLS_V12; }
	};

}

}

#endif
