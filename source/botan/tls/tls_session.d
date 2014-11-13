/*
* TLS Session
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.cert.x509.x509cert;
import botan.tls.tls_version;
import botan.tls.tls_ciphersuite;
import botan.tls.tls_magic;
import botan.tls.tls_server_info;
import botan.alloc.zeroize;
import botan.algo_base.symkey;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.asn1_str;
import botan.codec.pem;
import botan.constructs.cryptobox_psk;
import botan.utils.types;
import core.stdc.time : time_t;
import std.datetime;


/**
* Class representing a TLS session state
*/
struct Session
{
public:
	/**
	* New session (sets session start time)
	*/
	this(in Vector!ubyte session_identifier,
	     in Secure_Vector!ubyte master_secret,
	     Protocol_Version _version,
	     ushort ciphersuite,
	     ubyte compression_method,
	     Connection_Side side,
	     size_t fragment_size,
	     in Vector!X509_Certificate certs,
	     in Vector!ubyte ticket,
	     const Server_Information server_info,
	     in string srp_identifier)
	{
		m_start_time = Clock.currTime();
		m_identifier = session_identifier;
		m_session_ticket = ticket;
		m_master_secret = master_secret;
		m_version = _version;
		m_ciphersuite = ciphersuite;
		m_compression_method = compression_method;
		m_connection_side = side;
		m_fragment_size = fragment_size;
		m_peer_certs = certs;
		m_server_info = server_info;
		m_srp_identifier = srp_identifier;
	}

	/**
	* Load a session from DER representation (created by DER_encode)
	*/
	this(in ubyte* ber, size_t ber_len)
	{
		ubyte side_code = 0;
		
		ASN1_String server_hostname;
		ASN1_String server_service;
		size_t server_port;
		
		ASN1_String srp_identifier_str;
		
		ubyte major_version = 0, minor_version = 0;
		
		Vector!ubyte peer_cert_bits;
		
		size_t start_time = 0;
		
		BER_Decoder(ber, ber_len)
			.start_cons(ASN1_Tag.SEQUENCE)
				.decode_and_check(cast(size_t)(TLS_SESSION_PARAM_STRUCT_VERSION),
				                  "Unknown version in session structure")
				.decode_integer_type(start_time)
				.decode_integer_type(major_version)
				.decode_integer_type(minor_version)
				.decode(m_identifier, ASN1_Tag.OCTET_STRING)
				.decode(m_session_ticket, ASN1_Tag.OCTET_STRING)
				.decode_integer_type(m_ciphersuite)
				.decode_integer_type(m_compression_method)
				.decode_integer_type(side_code)
				.decode_integer_type(m_fragment_size)
				.decode(m_master_secret, ASN1_Tag.OCTET_STRING)
				.decode(peer_cert_bits, ASN1_Tag.OCTET_STRING)
				.decode(server_hostname)
				.decode(server_service)
				.decode(server_port)
				.decode(srp_identifier_str)
				.end_cons()
				.verify_end();
		
		m_version = Protocol_Version(major_version, minor_version);
		m_start_time = SysTime(unixTimeToStdTime(cast(time_t)start_time));
		m_connection_side = cast(Connection_Side)(side_code);
		
		m_server_info = Server_Information(server_hostname.value(),
		                                   server_service.value(),
		                                   server_port);
		
		m_srp_identifier = srp_identifier_str.value();
		
		if (!peer_cert_bits.empty)
		{
			auto certs = scoped!DataSource_Memory(&peer_cert_bits[0], peer_cert_bits.length);
			while(!certs.end_of_data())
				m_peer_certs.push_back(X509_Certificate(certs));
		}
	}

	/**
	* Load a session from PEM representation (created by PEM_encode)
	*/
	this(in string pem)
	{
		Secure_Vector!ubyte der = PEM.decode_check_label(pem, "SSL SESSION");
		
		this(&der[0], der.length);
	}

	/**
	* Encode this session data for storage
	* @warning if the master secret is compromised so is the
	* session traffic
	*/
	Secure_Vector!ubyte DER_encode() const
	{
		Vector!ubyte peer_cert_bits;
		for (size_t i = 0; i != m_peer_certs.length; ++i)
			peer_cert_bits += m_peer_certs[i].BER_encode();
		
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(cast(size_t)(TLS_SESSION_PARAM_STRUCT_VERSION))
				.encode(cast(size_t)(m_start_time.toUnixTime()))
				.encode(cast(size_t)(m_version.major_version()))
				.encode(cast(size_t)(m_version.minor_version()))
				.encode(m_identifier, ASN1_Tag.OCTET_STRING)
				.encode(m_session_ticket, ASN1_Tag.OCTET_STRING)
				.encode(cast(size_t)(m_ciphersuite))
				.encode(cast(size_t)(m_compression_method))
				.encode(cast(size_t)(m_connection_side))
				.encode(cast(size_t)(m_fragment_size))
				.encode(m_master_secret, ASN1_Tag.OCTET_STRING)
				.encode(peer_cert_bits, ASN1_Tag.OCTET_STRING)
				.encode(ASN1_String(m_server_info.hostname(), ASN1_Tag.UTF8_STRING))
				.encode(ASN1_String(m_server_info.service(), ASN1_Tag.UTF8_STRING))
				.encode(cast(size_t)(m_server_info.port()))
				.encode(ASN1_String(m_srp_identifier, ASN1_Tag.UTF8_STRING))
				.end_cons()
				.get_contents();
	}

	/**
	* Encrypt a session (useful for serialization or session tickets)
	*/
	Vector!ubyte encrypt(in SymmetricKey master_key,
		        		 RandomNumberGenerator rng) const
	{
		const auto der = this.DER_encode();
		
		return CryptoBox.encrypt(&der[0], der.length, master_key, rng);
	}

	/**
	* Decrypt a session created by encrypt
	* @param ctext the ciphertext returned by encrypt
	* @param ctext_size the size of ctext in bytes
	* @param key the same key used by the encrypting side
	*/
	static Session decrypt(in ubyte* buf, size_t buf_len,
	                const ref SymmetricKey master_key)
	{
		try
		{
			const auto ber = CryptoBox.decrypt(buf, buf_len, master_key);
			
			return Session(&ber[0], ber.length);
		}
		catch(Exception e)
		{
			throw new Decoding_Error("Failed to decrypt encrypted session -" ~
			                         string(e.msg));
		}
	}

	/**
	* Decrypt a session created by encrypt
	* @param ctext the ciphertext returned by encrypt
	* @param key the same key used by the encrypting side
	*/
	static  Session decrypt(in Vector!ubyte ctext,
											const ref SymmetricKey key)
	{
		return Session.decrypt(&ctext[0], ctext.length, key);
	}

	/**
	* Encode this session data for storage
	* @warning if the master secret is compromised so is the
	* session traffic
	*/
	string PEM_encode() const
	{
		return PEM.encode(this.DER_encode(), "SSL SESSION");
	}

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
	ubyte compression_method() const { return m_compression_method; }

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
	const Secure_Vector!ubyte master_secret() const
	{ return m_master_secret; }

	/**
	* Get the session identifier
	*/
	const Vector!ubyte session_id() const
	{ return m_identifier; }

	/**
	* Get the negotiated maximum fragment size (or 0 if default)
	*/
	size_t fragment_size() const { return m_fragment_size; }

	/**
	* Return the certificate chain of the peer (possibly empty)
	*/
	Vector!X509_Certificate peer_certs() const { return m_peer_certs; }

	/**
	* Get the wall clock time this session began
	*/
	SysTime start_time() const
	{ return m_start_time; }

	/**
	* Return how long this session has existed (in seconds)
	*/
	Duration session_age() const
	{
		return Clock.currTime() - m_start_time;
	}

	/**
	* Return the session ticket the server gave us
	*/
	const Vector!ubyte session_ticket() const { return m_session_ticket; }

	Server_Information server_info() const { return m_server_info; }

private:
	enum { TLS_SESSION_PARAM_STRUCT_VERSION = 0x2994e301 }

	SysTime m_start_time;

	Vector!ubyte m_identifier;
	Vector!ubyte m_session_ticket; // only used by client side
	Secure_Vector!ubyte m_master_secret;

	Protocol_Version m_version;
	ushort m_ciphersuite;
	ubyte m_compression_method;
	Connection_Side m_connection_side;

	size_t m_fragment_size;

	Vector!X509_Certificate m_peer_certs;
	Server_Information m_server_info; // optional
	string m_srp_identifier; // optional
}