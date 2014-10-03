/*
* TLS Session
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.x509cert;
import botan.tls_version;
import botan.tls_ciphersuite;
import botan.tls_magic;
import botan.tls_server_info;
import botan.secmem;
import botan.algo_base.symkey;
import chrono;
namespace TLS {

/**
* Class representing a TLS session state
*/
class Session
{
	public:

		/**
		* Uninitialized session
		*/
		Session() :
			m_start_time(SysTime::min()),
			m_version(),
			m_ciphersuite(0),
			m_compression_method(0),
			m_connection_side(cast(Connection_Side)(0)),
			m_fragment_size(0)
			{}

		/**
		* New session (sets session start time)
		*/
		Session(in Vector!byte session_id,
				  in SafeVector!byte master_secret,
				  Protocol_Version _version,
				  ushort ciphersuite,
				  byte compression_method,
				  Connection_Side side,
				  size_t fragment_size,
				  const Vector!( X509_Certificate )& peer_certs,
				  in Vector!byte session_ticket,
				  const Server_Information& server_info,
				  in string srp_identifier);

		/**
		* Load a session from DER representation (created by DER_encode)
		*/
		Session(in byte* ber, size_t ber_len);

		/**
		* Load a session from PEM representation (created by PEM_encode)
		*/
		Session(in string pem);

		/**
		* Encode this session data for storage
		* @warning if the master secret is compromised so is the
		* session traffic
		*/
		SafeVector!byte DER_encode() const;

		/**
		* Encrypt a session (useful for serialization or session tickets)
		*/
		Vector!( byte ) encrypt(in SymmetricKey key,
										  RandomNumberGenerator rng) const;		/**
		* Decrypt a session created by encrypt
		* @param ctext the ciphertext returned by encrypt
		* @param ctext_size the size of ctext in bytes
		* @param key the same key used by the encrypting side
		*/
		static Session decrypt(in byte* ctext,
									  size_t ctext_size,
									  const SymmetricKey& key);

		/**
		* Decrypt a session created by encrypt
		* @param ctext the ciphertext returned by encrypt
		* @param key the same key used by the encrypting side
		*/
		static  Session decrypt(in Vector!byte ctext,
												const SymmetricKey& key)
		{
			return Session::decrypt(&ctext[0], ctext.size(), key);
		}

		/**
		* Encode this session data for storage
		* @warning if the master secret is compromised so is the
		* session traffic
		*/
		string PEM_encode() const;

		/**
		* Get the version of the saved session
		*/
		Protocol_Version _version() const { return m_version; }

		/**
		* Get the ciphersuite code of the saved session
		*/
		ushort ciphersuite_code() const { return m_ciphersuite; }

		/**
		* Get the ciphersuite info of the saved session
		*/
		Ciphersuite ciphersuite() const { return Ciphersuite::by_id(m_ciphersuite); }

		/**
		* Get the compression method used in the saved session
		*/
		byte compression_method() const { return m_compression_method; }

		/**
		* Get which side of the connection the resumed session we are/were
		* acting as.
		*/
		Connection_Side side() const { return m_connection_side; }

		/**
		* Get the SRP identity (if sent by the client in the initial handshake)
		*/
		string srp_identifier() const { return m_srp_identifier; }

		/**
		* Get the saved master secret
		*/
		in SafeVector!byte master_secret() const
		{ return m_master_secret; }

		/**
		* Get the session identifier
		*/
		in Vector!byte session_id() const
		{ return m_identifier; }

		/**
		* Get the negotiated maximum fragment size (or 0 if default)
		*/
		size_t fragment_size() const { return m_fragment_size; }

		/**
		* Return the certificate chain of the peer (possibly empty)
		*/
		Vector!( X509_Certificate ) peer_certs() const { return m_peer_certs; }

		/**
		* Get the wall clock time this session began
		*/
		SysTime start_time() const
		{ return m_start_time; }

		/**
		* Return how long this session has existed (in seconds)
		*/
		std::chrono::seconds session_age() const;

		/**
		* Return the session ticket the server gave us
		*/
		in Vector!byte session_ticket() const { return m_session_ticket; }

		Server_Information server_info() const { return m_server_info; }

	private:
		enum { TLS_SESSION_PARAM_STRUCT_VERSION = 0x2994e301 };

		SysTime m_start_time;

		Vector!( byte ) m_identifier;
		Vector!( byte ) m_session_ticket; // only used by client side
		SafeVector!byte m_master_secret;

		Protocol_Version m_version;
		ushort m_ciphersuite;
		byte m_compression_method;
		Connection_Side m_connection_side;

		size_t m_fragment_size;

		Vector!( X509_Certificate ) m_peer_certs;
		Server_Information m_server_info; // optional
		string m_srp_identifier; // optional
};

}