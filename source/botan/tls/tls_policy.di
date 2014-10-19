/*
* Hooks for application level policies on TLS connections
* (C) 2004-2006,2013 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.tls_version;
import botan.tls_ciphersuite;
import botan.cert.x509.x509cert;
import botan.pubkey.algo.dl_group;
import vector;
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
		abstract Vector!string allowed_ciphers() const;

		/**
		* Returns a list of hash algorithms we are willing to use for
		* signatures, in order of preference.
		*/
		abstract Vector!string allowed_signature_hashes() const;

		/**
		* Returns a list of MAC algorithms we are willing to use.
		*/
		abstract Vector!string allowed_macs() const;

		/**
		* Returns a list of key exchange algorithms we are willing to
		* use, in order of preference. Allowed values: DH, empty string
		* (representing RSA using server certificate key)
		*/
		abstract Vector!string allowed_key_exchange_methods() const;

		/**
		* Returns a list of signature algorithms we are willing to
		* use, in order of preference. Allowed values RSA and DSA.
		*/
		abstract Vector!string allowed_signature_methods() const;

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
		{ return Vector!string({"AES-128/GCM"}); }

		override Vector!string allowed_signature_hashes() const
		{ return Vector!string({"SHA-256"}); }

		override Vector!string allowed_macs() const
		{ return Vector!string({"AEAD"}); }

		override Vector!string allowed_key_exchange_methods() const
		{ return Vector!string({"ECDH"}); }

		override Vector!string allowed_signature_methods() const
		{ return Vector!string({"ECDSA"}); }

		override Vector!string allowed_ecc_curves() const
		{ return Vector!string({"secp256r1"}); }

		override bool acceptable_protocol_version(Protocol_Version _version) const
		{ return _version == Protocol_Version::TLS_V12; }
};

/**
* Policy for DTLS. We require DTLS v1.2 and an AEAD mode
*/
class Datagram_Policy : Policy
{
	public:
		override Vector!string allowed_macs() const
		{ return Vector!string({"AEAD"}); }

		override bool acceptable_protocol_version(Protocol_Version _version) const
		{ return _version == Protocol_Version::DTLS_V12; }
};

}