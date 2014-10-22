/*
* TLS Messages
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_messages;

import botan.tls.tls_handshake_state;
import botan.tls.tls_session_key;
import botan.internal.stl_util;

public import botan.algo_base.sym_algo;
public import botan.tls.tls_handshake_msg;
public import botan.tls.tls_session;
public import botan.tls.tls_policy;
public import botan.tls.tls_ciphersuite;
public import botan.tls.tls_reader;
public import botan.tls.tls_extensions;
public import botan.tls.tls_handshake_io;
public import botan.tls.tls_version;
public import botan.tls.tls_handshake_hash;
public import botan.tls.tls_magic;
import botan.constructs.srp6;
public import botan.credentials.credentials_manager;
import botan.utils.loadstor;
import botan.constructs.srp6;
import botan.math.bigint.bigint;
import botan.pubkey.pkcs8;
import botan.pubkey.pubkey;
import botan.pubkey.algo.dh;
import botan.pubkey.algo.ecdh;
import botan.pubkey.algo.rsa;
import botan.cert.x509.x509cert;
import botan.asn1.oid_lookup.oids;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.loadstor;
import botan.utils.types;
import botan.libstate.lookup;
import botan.rng.rng;
import botan.utils.types : Unique;
import std.datetime;
import botan.utils.types;
import string;

enum {
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV		  = 0x00FF
};

/**
* TLS Handshake Message Base Class
*/
class Handshake_Message
{
public:
	abstract Handshake_Type type() const;
	
	abstract Vector!ubyte serialize() const;
	
	~this() {}
};

/**
* DTLS Hello Verify Request
*/
class Hello_Verify_Request : Handshake_Message
{
public:
	override Vector!ubyte serialize() const
	{
		/* DTLS 1.2 server implementations SHOULD use DTLS version 1.0
			regardless of the version of TLS that is expected to be
			negotiated (RFC 6347, section 4.2.1)
		*/
			
		Protocol_Version format_version(Protocol_Version.DTLS_V10);
		
		Vector!ubyte bits;
		bits.push_back(format_version.major_version());
		bits.push_back(format_version.minor_version());
		bits.push_back(cast(ubyte)(m_cookie.length));
		bits += m_cookie;
		return bits;
	}

	override Handshake_Type type() const { return HELLO_VERIFY_REQUEST; }

	Vector!ubyte cookie() const { return m_cookie; }

	this(in Vector!ubyte buf)
	{
		if (buf.length < 3)
			throw new Decoding_Error("Hello verify request too small");
		
		Protocol_Version version_ = Protocol_Version(buf[0], buf[1]);
		
		if (version_ != Protocol_Version.DTLS_V10 &&
		    version_ != Protocol_Version.DTLS_V12)
		{
			throw new Decoding_Error("Unknown version from server in hello verify request");
		}
		
		if (cast(size_t)(buf[2]) + 3 != buf.length)
			throw new Decoding_Error("Bad length in hello verify request");
		
		m_cookie.assign(&buf[3], &buf[buf.length]);
	}

	this(in Vector!ubyte client_hello_bits,
	     in string client_identity,
	     const ref SymmetricKey secret_key)
	{
		Unique!MessageAuthenticationCode hmac = get_mac("HMAC(SHA-256)");
		hmac.set_key(secret_key);
		
		hmac.update_be(client_hello_bits.length);
		hmac.update(client_hello_bits);
		hmac.update_be(client_identity.length);
		hmac.update(client_identity);
		
		m_cookie = unlock(hmac.flush());
	}
private:
	Vector!ubyte m_cookie;
};

/**
* Client Hello Message
*/
class Client_Hello : Handshake_Message
{
public:
	override Handshake_Type type() const { return CLIENT_HELLO; }

	Protocol_Version _version() const { return m_version; }

	const Vector!ubyte random() const { return m_random; }

	const Vector!ubyte session_id() const { return m_session_id; }

	Vector!ushort ciphersuites() const { return m_suites; }

	Vector!ubyte compression_methods() const { return m_comp_methods; }

	/*
	* Check if we offered this ciphersuite
	*/
	bool offered_suite(ushort ciphersuite) const
	{
		for (size_t i = 0; i != m_suites.length; ++i)
			if (m_suites[i] == ciphersuite)
				return true;
		return false;
	}

	Vector!( Pair!(string, string) ) supported_algos() const
	{
		if (Signature_Algorithms* sigs = m_extensions.get!Signature_Algorithms())
			return sigs.supported_signature_algorthms();
		return Vector!( Pair!(string, string) )();
	}

	Vector!string supported_ecc_curves() const
	{
		if (Supported_Elliptic_Curves* ecc = m_extensions.get!Supported_Elliptic_Curves())
			return ecc.curves();
		return Vector!string();
	}

	string sni_hostname() const
	{
		if (Server_Name_Indicator* sni = m_extensions.get!Server_Name_Indicator())
			return sni.host_name();
		return "";
	}

	string srp_identifier() const
	{
		if (SRP_Identifier* srp = m_extensions.get!SRP_Identifier())
			return srp.identifier();
		return "";
	}

	bool secure_renegotiation() const
	{
		return m_extensions.get!Renegotiation_Extension();
	}

	Vector!ubyte renegotiation_info() const
	{
		if (Renegotiation_Extension reneg = m_extensions.get!Renegotiation_Extension())
			return reneg.renegotiation_info();
		return Vector!ubyte();
	}

	bool next_protocol_notification() const
	{
		return m_extensions.get!Next_Protocol_Notification();
	}

	size_t fragment_size() const
	{
		if (Maximum_Fragment_Length* frag = m_extensions.get!Maximum_Fragment_Length())
			return frag.fragment_size();
		return 0;
	}

	bool supports_session_ticket() const
	{
		return m_extensions.get!Session_Ticket();
	}

	Vector!ubyte session_ticket() const
	{
		if (Session_Ticket* ticket = m_extensions.get!Session_Ticket())
			return ticket.contents();
		return Vector!ubyte();
	}

	bool supports_heartbeats() const
	{
		return m_extensions.get!Heartbeat_Support_Indicator();
	}

	bool peer_can_send_heartbeats() const
	{
		if (Heartbeat_Support_Indicator hb = m_extensions.get!Heartbeat_Support_Indicator())
			return hb.peer_allowed_to_send();
		return false;
	}

	void update_hello_cookie(in Hello_Verify_Request hello_verify)
	{
		if (!m_version.is_datagram_protocol())
			throw new Exception("Cannot use hello cookie with stream protocol");
		
		m_hello_cookie = hello_verify.cookie();
	}

	Handshake_Extension_Type[] extension_types() const
	{ return m_extensions.extension_types(); }

	/*
	* Create a new Client Hello message
	*/
	this(Handshake_IO io,
	     Handshake_Hash hash,
	     Protocol_Version _version,
	     const Policy policy,
	     RandomNumberGenerator rng,
	     in Vector!ubyte reneg_info,
	     bool next_protocol,
	     in string hostname,
	     in string srp_identifier) 
	{
		m_version = _version;
		m_random = make_hello_random(rng);
		m_suites = policy.ciphersuite_list(m_version, (srp_identifier != ""));
		m_comp_methods = policy.compression();
		m_extensions.add(new Renegotiation_Extension(reneg_info));
		m_extensions.add(new SRP_Identifier(srp_identifier));
		m_extensions.add(new Server_Name_Indicator(hostname));
		m_extensions.add(new Session_Ticket());
		m_extensions.add(new Supported_Elliptic_Curves(policy.allowed_ecc_curves()));
		
		if (policy.negotiate_heartbeat_support())
			m_extensions.add(new Heartbeat_Support_Indicator(true));
		
		if (m_version.supports_negotiable_signature_algorithms())
			m_extensions.add(new Signature_Algorithms(policy.allowed_signature_hashes(),
			                                          policy.allowed_signature_methods()));
		
		if (reneg_info.empty() && next_protocol)
			m_extensions.add(new Next_Protocol_Notification());
		
		hash.update(io.send(this));
	}


	/*
	* Create a new Client Hello message (session resumption case)
	*/
	this(Handshake_IO io,
	     Handshake_Hash hash,
	     const Policy policy,
	     RandomNumberGenerator rng,
	     in Vector!ubyte reneg_info,
	     const Session session,
	     bool next_protocol = false)
	{ 
		m_version = session._version();
		m_session_id = session.session_id();
		m_random = make_hello_random(rng);
		m_suites = policy.ciphersuite_list(m_version, (session.srp_identifier() != ""));
		m_comp_methods = policy.compression();
		if (!value_exists(m_suites, session.ciphersuite_code()))
			m_suites.push_back(session.ciphersuite_code());
		
		if (!value_exists(m_comp_methods, session.compression_method()))
			m_comp_methods.push_back(session.compression_method());
		
		m_extensions.add(new Renegotiation_Extension(reneg_info));
		m_extensions.add(new SRP_Identifier(session.srp_identifier()));
		m_extensions.add(new Server_Name_Indicator(session.server_info().hostname()));
		m_extensions.add(new Session_Ticket(session.session_ticket()));
		m_extensions.add(new Supported_Elliptic_Curves(policy.allowed_ecc_curves()));
		
		if (policy.negotiate_heartbeat_support())
			m_extensions.add(new Heartbeat_Support_Indicator(true));
		
		if (session.fragment_size() != 0)
			m_extensions.add(new Maximum_Fragment_Length(session.fragment_size()));
		
		if (m_version.supports_negotiable_signature_algorithms())
			m_extensions.add(new Signature_Algorithms(policy.allowed_signature_hashes(),
			                                          policy.allowed_signature_methods()));
		
		if (reneg_info.empty() && next_protocol)
			m_extensions.add(new Next_Protocol_Notification());
		
		hash.update(io.send(this));
	}

	/*
	* Read a counterparty client hello
	*/
	this(in Vector!ubyte buf, Handshake_Type type)
	{
		if (type == CLIENT_HELLO)
			deserialize(buf);
		else
			deserialize_sslv2(buf);
	}

private:
	/*
	* Serialize a Client Hello message
	*/
	override Vector!ubyte serialize() const
	{
		Vector!ubyte buf;
		
		buf.push_back(m_version.major_version());
		buf.push_back(m_version.minor_version());
		buf += m_random;
		
		append_tls_length_value(buf, m_session_id, 1);
		
		if (m_version.is_datagram_protocol())
			append_tls_length_value(buf, m_hello_cookie, 1);
		
		append_tls_length_value(buf, m_suites, 2);
		append_tls_length_value(buf, m_comp_methods, 1);
		
		/*
		* May not want to send extensions at all in some cases. If so,
		* should include SCSV value (if reneg info is empty, if not we are
		* renegotiating with a modern server)
		*/
		
		buf += m_extensions.serialize();
		
		return buf;
	}

	/*
	* Deserialize a Client Hello message
	*/
	void deserialize(in Vector!ubyte buf)
	{
		if (buf.length == 0)
			throw new Decoding_Error("Client_Hello: Packet corrupted");
		
		if (buf.length < 41)
			throw new Decoding_Error("Client_Hello: Packet corrupted");
		
		TLS_Data_Reader reader = TLS_Data_Reader("ClientHello", buf);
		
		const ubyte major_version = reader.get_byte();
		const ubyte minor_version = reader.get_byte();
		
		m_version = Protocol_Version(major_version, minor_version);
		
		m_random = reader.get_fixed!ubyte(32);
		
		if (m_version.is_datagram_protocol())
			m_hello_cookie = reader.get_range!ubyte(1, 0, 255);
		
		m_session_id = reader.get_range!ubyte(1, 0, 32);
		
		m_suites = reader.get_range_vector!ushort(2, 1, 32767);
		
		m_comp_methods = reader.get_range_vector!ubyte(1, 1, 255);
		
		m_extensions.deserialize(reader);
		
		if (offered_suite(cast(ushort)(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
		{
			if (Renegotiation_Extension reneg = m_extensions.get!Renegotiation_Extension())
			{
				if (!reneg.renegotiation_info().empty())
					throw new TLS_Exception(Alert.HANDSHAKE_FAILURE,
					                        "Client send renegotiation SCSV and non-empty extension");
			}
			else
			{
				// add fake extension
				m_extensions.add(new Renegotiation_Extension());
			}
		}
	}

	void deserialize_sslv2(in Vector!ubyte buf)
	{
		if (buf.length < 12 || buf[0] != 1)
			throw new Decoding_Error("Client_Hello: SSLv2 hello corrupted");
		
		const size_t cipher_spec_len = make_ushort(buf[3], buf[4]);
		const size_t m_session_id_len = make_ushort(buf[5], buf[6]);
		const size_t challenge_len = make_ushort(buf[7], buf[8]);
		
		const size_t expected_size =
			(9 + m_session_id_len + cipher_spec_len + challenge_len);
		
		if (buf.length != expected_size)
			throw new Decoding_Error("Client_Hello: SSLv2 hello corrupted");
		
		if (m_session_id_len != 0 || cipher_spec_len % 3 != 0 ||
		    (challenge_len < 16 || challenge_len > 32))
		{
			throw new Decoding_Error("Client_Hello: SSLv2 hello corrupted");
		}
		
		m_version = Protocol_Version(buf[1], buf[2]);
		
		for (size_t i = 9; i != 9 + cipher_spec_len; i += 3)
		{
			if (buf[i] != 0) // a SSLv2 cipherspec; ignore it
				continue;
			
			m_suites.push_back(make_ushort(buf[i+1], buf[i+2]));
		}
		
		m_random.resize(challenge_len);
		copy_mem(&m_random[0], &buf[9+cipher_spec_len+m_session_id_len], challenge_len);
		
		if (offered_suite(cast(ushort)(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
			m_extensions.add(new Renegotiation_Extension());
	}

	Protocol_Version m_version;
	Vector!ubyte m_session_id;
	Vector!ubyte m_random;
	Vector!ushort m_suites;
	Vector!ubyte m_comp_methods;
	Vector!ubyte m_hello_cookie; // DTLS only

	Extensions m_extensions;
};

/**
* Server Hello Message
*/
class Server_Hello : Handshake_Message
{
public:
	override Handshake_Type type() const { return SERVER_HELLO; }

	Protocol_Version _version() const { return m_version; }

	const Vector!ubyte random() const { return m_random; }

	const Vector!ubyte session_id() const { return m_session_id; }

	ushort ciphersuite() const { return m_ciphersuite; }

	ubyte compression_method() const { return m_comp_method; }

	bool secure_renegotiation() const
	{
		return m_extensions.get!Renegotiation_Extension();
	}

	Vector!ubyte renegotiation_info() const
	{
		if (Renegotiation_Extension reneg = m_extensions.get!Renegotiation_Extension())
			return reneg.renegotiation_info();
		return Vector!ubyte();
	}

	bool next_protocol_notification() const
	{
		return m_extensions.get!Next_Protocol_Notification();
	}

	Vector!string next_protocols() const
	{
		if (Next_Protocol_Notification npn = m_extensions.get!Next_Protocol_Notification())
			return npn.protocols();
		return Vector!string();
	}

	size_t fragment_size() const
	{
		if (Maximum_Fragment_Length frag = m_extensions.get!Maximum_Fragment_Length())
			return frag.fragment_size();
		return 0;
	}

	bool supports_session_ticket() const
	{
		return m_extensions.get!Session_Ticket();
	}

	bool supports_heartbeats() const
	{
		return m_extensions.get!Heartbeat_Support_Indicator();
	}

	bool peer_can_send_heartbeats() const
	{
		if (Heartbeat_Support_Indicator hb = m_extensions.get!Heartbeat_Support_Indicator())
			return hb.peer_allowed_to_send();
		return false;
	}

	Handshake_Extension_Type[] extension_types() const
	{ return m_extensions.extension_types(); }

	/*
	* Create a new Server Hello message
	*/
	this(Handshake_IO io,
	     Handshake_Hash hash,
	     const Policy policy,
	     in Vector!ubyte session_id,
	     Protocol_Version ver,
	     ushort ciphersuite,
	     ubyte compression,
	     size_t max_fragment_size,
	     bool client_has_secure_renegotiation,
	     in Vector!ubyte reneg_info,
	     bool offer_session_ticket,
	     bool client_has_npn,
	     const Vector!string next_protocols,
	     bool client_has_heartbeat,
	     RandomNumberGenerator rng) 
	{
		m_version = ver;
		m_session_id = session_id;
		m_random = make_hello_random(rng);
		m_ciphersuite = ciphersuite;
		m_comp_method = compression;
		
		if (client_has_heartbeat && policy.negotiate_heartbeat_support())
			m_extensions.add(new Heartbeat_Support_Indicator(true));
		
		/*
		* Even a client that offered SSLv3 and sent the SCSV will get an
		* extension back. This is probably the right thing to do.
		*/
		if (client_has_secure_renegotiation)
			m_extensions.add(new Renegotiation_Extension(reneg_info));
		
		if (max_fragment_size)
			m_extensions.add(new Maximum_Fragment_Length(max_fragment_size));
		
		if (client_has_npn)
			m_extensions.add(new Next_Protocol_Notification(next_protocols));
		
		if (offer_session_ticket)
			m_extensions.add(new Session_Ticket());
		
		hash.update(io.send(this));
	}

	/*
	* Deserialize a Server Hello message
	*/
	this(in Vector!ubyte buf)
	{
		if (buf.length < 38)
			throw new Decoding_Error("Server_Hello: Packet corrupted");
		
		TLS_Data_Reader reader = TLS_Data_Reader("ServerHello", buf);
		
		const ubyte major_version = reader.get_byte();
		const ubyte minor_version = reader.get_byte();
		
		m_version = Protocol_Version(major_version, minor_version);
		
		m_random = reader.get_fixed!ubyte(32);
		
		m_session_id = reader.get_range!ubyte(1, 0, 32);
		
		m_ciphersuite = reader.get_ushort();
		
		m_comp_method = reader.get_byte();
		
		m_extensions.deserialize(reader);
	}
private:
	/*
	* Serialize a Server Hello message
	*/
	override Vector!ubyte serialize() const
	{
		Vector!ubyte buf;
		
		buf.push_back(m_version.major_version());
		buf.push_back(m_version.minor_version());
		buf += m_random;
		
		append_tls_length_value(buf, m_session_id, 1);
		
		buf.push_back(get_byte(0, m_ciphersuite));
		buf.push_back(get_byte(1, m_ciphersuite));
		
		buf.push_back(m_comp_method);
		
		buf += m_extensions.serialize();
		
		return buf;
	}

	Protocol_Version m_version;
	Vector!ubyte m_session_id, m_random;
	ushort m_ciphersuite;
	ubyte m_comp_method;

	Extensions m_extensions;
};

/**
* Client Key Exchange Message
*/
class Client_Key_Exchange : Handshake_Message
{
public:
	override Handshake_Type type() const { return CLIENT_KEX; }

	const SafeVector!ubyte pre_master_secret() const
	{ return m_pre_master; }

	/*
	* Read a Client Key Exchange message
	*/
	this(in Vector!ubyte contents,
	     const Handshake_State state,
	     const Private_Key server_rsa_kex_key,
	     Credentials_Manager creds,
	     const Policy policy,
	     RandomNumberGenerator rng)
	{
		const string kex_algo = state.ciphersuite().kex_algo();
		
		if (kex_algo == "RSA")
		{
			assert(state.server_certs() && !state.server_certs().cert_chain().empty(),
			             "RSA key exchange negotiated so server sent a certificate");
			
			if (!server_rsa_kex_key)
				throw new Internal_Error("Expected RSA kex but no server kex key set");
			
			if (!cast(const RSA_PrivateKey)(server_rsa_kex_key))
				throw new Internal_Error("Expected RSA key but got " ~ server_rsa_kex_key.algo_name);
			
			auto decryptor = scoped!PK_Decryptor_EME(*server_rsa_kex_key, "PKCS1v15");
			
			Protocol_Version client_version = state.client_hello()._version();
			
			/*
			* This is used as the pre-master if RSA decryption fails.
			* Otherwise we can be used as an oracle. See Bleichenbacher
			* "Chosen Ciphertext Attacks against Protocols Based on RSA
			* Encryption Standard PKCS #1", Crypto 98
			*
			* Create it here instead if in the catch clause as otherwise we
			* expose a timing channel WRT the generation of the fake value.
			* Some timing channel likely remains due to exception handling
			* and the like.
			*/
			SafeVector!ubyte fake_pre_master = rng.random_vec(48);
			fake_pre_master[0] = client_version.major_version();
			fake_pre_master[1] = client_version.minor_version();
			
			try
			{
				if (state._version() == Protocol_Version.SSL_V3)
				{
					m_pre_master = decryptor.decrypt(contents);
				}
				else
				{
					TLS_Data_Reader reader = TLS_Data_Reader("ClientKeyExchange", contents);
					m_pre_master = decryptor.decrypt(reader.get_range!ubyte(2, 0, 65535));
				}
				
				if (m_pre_master.length != 48 ||
				    client_version.major_version() != m_pre_master[0] ||
					client_version.minor_version() != m_pre_master[1])
				{
					throw new Decoding_Error("Client_Key_Exchange: Secret corrupted");
				}
			}
			catch
			{
				m_pre_master = fake_pre_master;
			}
		}
		else
		{
			TLS_Data_Reader reader = TLS_Data_Reader("ClientKeyExchange", contents);
			
			SymmetricKey psk;
			
			if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
			{
				const string psk_identity = reader.get_string(2, 0, 65535);
				
				psk = creds.psk("tls-server",
				                state.client_hello().sni_hostname(),
				                psk_identity);
				
				if (psk.length() == 0)
				{
					if (policy.hide_unknown_users())
						psk = SymmetricKey(rng, 16);
					else
						throw new TLS_Exception(Alert.UNKNOWN_PSK_IDENTITY,
						                        "No PSK for identifier " ~ psk_identity);
				}
			}
			
			if (kex_algo == "PSK")
			{
				Vector!ubyte zeros = Vector!ubyte(psk.length());
				append_tls_length_value(m_pre_master, zeros, 2);
				append_tls_length_value(m_pre_master, psk.bits_of(), 2);
			}
			else if (kex_algo == "SRP_SHA")
			{
				SRP6_Server_Session srp = state.server_kex().server_srp_params();
				
				m_pre_master = srp.step2(BigInt.decode(reader.get_range!ubyte(2, 0, 65535))).bits_of();
			}
			else if (kex_algo == "DH" || kex_algo == "DHE_PSK" ||
			         kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
			{
				const Private_Key private_key = state.server_kex().server_kex_key();
				
				const PK_Key_Agreement_Key ka_key = cast(const PK_Key_Agreement_Key)(private_key);
				
				if (!ka_key)
					throw new Internal_Error("Expected key agreement key type but got " ~
					                         private_key.algo_name);
				
				try
				{
					auto ka = scoped!PK_Key_Agreement(ka_key, "Raw");
					
					Vector!ubyte client_pubkey;
					
					if (ka_key.algo_name == "DH")
						client_pubkey = reader.get_range!ubyte(2, 0, 65535);
					else
						client_pubkey = reader.get_range!ubyte(1, 0, 255);
					
					SafeVector!ubyte shared_secret = ka.derive_key(0, client_pubkey).bits_of();
					
					if (ka_key.algo_name == "DH")
						shared_secret = strip_leading_zeros(shared_secret);
					
					if (kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
					{
						append_tls_length_value(m_pre_master, shared_secret, 2);
						append_tls_length_value(m_pre_master, psk.bits_of(), 2);
					}
					else
						m_pre_master = shared_secret;
				}
				catch(Exception e)
				{
					/*
					* Something failed in the DH computation. To avoid possible
					* timing attacks, randomize the pre-master output and carry
					* on, allowing the protocol to fail later in the finished
					* checks.
					*/
					m_pre_master = rng.random_vec(ka_key.public_value().length);
				}
			}
			else
				throw new Internal_Error("Client_Key_Exchange: Unknown kex type " ~ kex_algo);
		}
	}

	/*
	* Create a new Client Key Exchange message
	*/
	this(Handshake_IO io,
	     Handshake_State state,
	     const Policy policy,
	     Credentials_Manager creds,
	     const Public_Key server_public_key,
	     in string hostname,
	     RandomNumberGenerator rng)
	{
		const string kex_algo = state.ciphersuite().kex_algo();
		
		if (kex_algo == "PSK")
		{
			string identity_hint = "";
			
			if (state.server_kex())
			{
				TLS_Data_Reader reader = TLS_Data_Reader("ClientKeyExchange", state.server_kex().params());
				identity_hint = reader.get_string(2, 0, 65535);
			}
			
			const string hostname = state.client_hello().sni_hostname();
			
			const string psk_identity = creds.psk_identity("tls-client",
			                                               hostname,
			                                               identity_hint);
			
			append_tls_length_value(m_key_material, psk_identity, 2);
			
			SymmetricKey psk = creds.psk("tls-client", hostname, psk_identity);
			
			Vector!ubyte zeros = Vector!ubyte(psk.length());
			
			append_tls_length_value(m_pre_master, zeros, 2);
			append_tls_length_value(m_pre_master, psk.bits_of(), 2);
		}
		else if (state.server_kex())
		{
			TLS_Data_Reader reader = TLS_Data_Reader("ClientKeyExchange", state.server_kex().params());
			
			SymmetricKey psk;
			
			if (kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
			{
				string identity_hint = reader.get_string(2, 0, 65535);
				
				const string hostname = state.client_hello().sni_hostname();
				
				const string psk_identity = creds.psk_identity("tls-client",
				                                               hostname,
				                                               identity_hint);
				
				append_tls_length_value(m_key_material, psk_identity, 2);
				
				psk = creds.psk("tls-client", hostname, psk_identity);
			}
			
			if (kex_algo == "DH" || kex_algo == "DHE_PSK")
			{
				BigInt p = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
				BigInt g = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
				BigInt Y = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
				
				if (reader.remaining_bytes())
					throw new Decoding_Error("Bad params size for DH key exchange");
				
				if (p.bits() < policy.minimum_dh_group_size())
					throw new TLS_Exception(Alert.INSUFFICIENT_SECURITY,
					                        "Server sent DH group of " ~
					                        std.conv.to!string(p.bits()) +
					                        " bits, policy requires at least " ~
					                        std.conv.to!string(policy.minimum_dh_group_size()));
				
				/*
				* A basic check for key validity. As we do not know q here we
				* cannot check that Y is in the right subgroup. However since
				* our key is ephemeral there does not seem to be any
				* advantage to bogus keys anyway.
				*/
				if (Y <= 1 || Y >= p - 1)
					throw new TLS_Exception(Alert.INSUFFICIENT_SECURITY,
					                        "Server sent bad DH key for DHE exchange");
				
				DL_Group group = DL_Group(p, g);
				
				if (!group.verify_group(rng, true))
					throw new Internal_Error("DH group failed validation, possible attack");
				auto counterparty_key = scoped!DH_PublicKey(group, Y);
				
				auto priv_key = scoped!DH_PrivateKey(rng, group);
				
				auto ka = scoped!PK_Key_Agreement(priv_key, "Raw");
				
				SafeVector!ubyte dh_secret = strip_leading_zeros(
					ka.derive_key(0, counterparty_key.public_value()).bits_of());
				
				if (kex_algo == "DH")
					m_pre_master = dh_secret;
				else
				{
					append_tls_length_value(m_pre_master, dh_secret, 2);
					append_tls_length_value(m_pre_master, psk.bits_of(), 2);
				}
				
				append_tls_length_value(m_key_material, priv_key.public_value(), 2);
			}
			else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
			{
				const ubyte curve_type = reader.get_byte();
				
				if (curve_type != 3)
					throw new Decoding_Error("Server sent non-named ECC curve");
				
				const ushort curve_id = reader.get_ushort();
				
				const string name = Supported_Elliptic_Curves.curve_id_to_name(curve_id);
				
				if (name == "")
					throw new Decoding_Error("Server sent unknown named curve " ~ std.conv.to!string(curve_id));
				
				EC_Group group = EC_Group(name);
				
				Vector!ubyte ecdh_key = reader.get_range!ubyte(1, 1, 255);
				
				auto counterparty_key = scoped!ECDH_PublicKey(group, OS2ECP(ecdh_key, group.get_curve()));
				
				auto priv_key = scoped!ECDH_PrivateKey(rng, group);
				
				auto ka = scoped!PK_Key_Agreement(priv_key, "Raw");
				
				SafeVector!ubyte ecdh_secret =
					ka.derive_key(0, counterparty_key.public_value()).bits_of();
				
				if (kex_algo == "ECDH")
					m_pre_master = ecdh_secret;
				else
				{
					append_tls_length_value(m_pre_master, ecdh_secret, 2);
					append_tls_length_value(m_pre_master, psk.bits_of(), 2);
				}
				
				append_tls_length_value(m_key_material, priv_key.public_value(), 1);
			}
			else if (kex_algo == "SRP_SHA")
			{
				const BigInt N = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
				const BigInt g = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
				Vector!ubyte salt = reader.get_range!ubyte(1, 1, 255);
				const BigInt B = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
				
				const string srp_group = srp6_group_identifier(N, g);
				
				const string srp_identifier =
					creds.srp_identifier("tls-client", hostname);
				
				const string srp_password =
					creds.srp_password("tls-client", hostname, srp_identifier);
				
				Pair!(BigInt, SymmetricKey) srp_vals =
					srp6_client_agree(srp_identifier,
					                  srp_password,
					                  srp_group,
					                  "SHA-1",
					                  salt,
					                  B,
					                  rng);
				
				append_tls_length_value(m_key_material, BigInt.encode(srp_vals.first), 2);
				m_pre_master = srp_vals.second.bits_of();
			}
			else
			{
				throw new Internal_Error("Client_Key_Exchange: Unknown kex " ~
				                         kex_algo);
			}
			
			reader.assert_done();
		}
		else
		{
			// No server key exchange msg better mean RSA kex + RSA key in cert
			
			if (kex_algo != "RSA")
				throw new Unexpected_Message("No server kex but negotiated kex " ~ kex_algo);
			
			if (!server_public_key)
				throw new Internal_Error("No server public key for RSA exchange");
			
			if (auto rsa_pub = cast(const RSA_PublicKey)(server_public_key))
			{
				const Protocol_Version offered_version = state.client_hello()._version();
				
				m_pre_master = rng.random_vec(48);
				m_pre_master[0] = offered_version.major_version();
				m_pre_master[1] = offered_version.minor_version();
				
				auto encryptor = scoped!PK_Encryptor_EME(rsa_pub, "PKCS1v15");
				
				Vector!ubyte encrypted_key = encryptor.encrypt(m_pre_master, rng);
				
				if (state._version() == Protocol_Version.SSL_V3)
					m_key_material = encrypted_key; // no length field
				else
					append_tls_length_value(m_key_material, encrypted_key, 2);
			}
			else
				throw new TLS_Exception(Alert.HANDSHAKE_FAILURE,
				                        "Expected a RSA key in server cert but got " ~
				                        server_public_key.algo_name);
		}
		
		state.hash().update(io.send(this));
	}


private:
	override Vector!ubyte serialize() const
	{ return m_key_material; }

	Vector!ubyte m_key_material;
	SafeVector!ubyte m_pre_master;
};

/**
* Certificate Message
*/
class Certificate : Handshake_Message
{
public:
	override Handshake_Type type() const { return CERTIFICATE; }
	const ref Vector!X509_Certificate cert_chain() const { return m_certs; }

	size_t count() const { return m_certs.length; }
	bool empty() const { return m_certs.empty(); }

	/**
	* Create a new Certificate message
	*/
	this(Handshake_IO io,
	     Handshake_Hash hash,
	     const ref Vector!X509_Certificate cert_list)
	{
		m_certs = cert_list;
		hash.update(io.send(this));
	}

	/**
	* Deserialize a Certificate message
	*/
	this(in Vector!ubyte buf)
	{
		if (buf.length < 3)
			throw new Decoding_Error("Certificate: Message malformed");
		
		const size_t total_size = make_uint(0, buf[0], buf[1], buf[2]);
		
		if (total_size != buf.length - 3)
			throw new Decoding_Error("Certificate: Message malformed");
		
		const ubyte* certs = &buf[3];
		
		while(true)
		{
			size_t remaining_bytes = &buf[buf.length] - certs;
			if (remaining_bytes <= 0)
				break;
			if (remaining_bytes < 3)
				throw new Decoding_Error("Certificate: Message malformed");
			
			const size_t cert_size = make_uint(0, certs[0], certs[1], certs[2]);
			
			if (remaining_bytes < (3 + cert_size))
				throw new Decoding_Error("Certificate: Message malformed");
			
			auto cert_buf = scoped!DataSource_Memory(&certs[3], cert_size);
			m_certs.push_back(X509_Certificate(cert_buf));
			
			certs += cert_size + 3;
		}
	}

private:
	/**
	* Serialize a Certificate message
	*/
	override Vector!ubyte serialize() const
	{
		Vector!ubyte buf = Vector!ubyte(3);
		
		for (size_t i = 0; i != m_certs.length; ++i)
		{
			Vector!ubyte raw_cert = m_certs[i].BER_encode();
			const size_t cert_size = raw_cert.length;
			for (size_t i = 0; i != 3; ++i)
				buf.push_back(get_byte!uint(i+1, cert_size));
			buf += raw_cert;
		}
		
		const size_t buf_size = buf.length - 3;
		for (size_t i = 0; i != 3; ++i)
			buf[i] = get_byte!uint(i+1, buf_size);
		
		return buf;
	}

	Vector!(X509_Certificate) m_certs;
};

/**
* Certificate Request Message
*/
class Certificate_Req : Handshake_Message
{
public:
	override Handshake_Type type() const { return CERTIFICATE_REQUEST; }

	const Vector!string& acceptable_cert_types() const
	{ return m_cert_key_types; }

	Vector!( X509_DN ) acceptable_CAs() const { return m_names; }

	Vector!( Pair!(string, string)  ) supported_algos() const
	{ return m_supported_algos; }

	/**
	* Create a new Certificate Request message
	*/
	this(Handshake_IO io,
	     Handshake_Hash hash,
	     const Policy policy,
	     const ref Vector!X509_DN ca_certs,
	     Protocol_Version _version) 
	{
		m_names = ca_certs;
		m_cert_key_types = [ "RSA", "DSA", "ECDSA" ];
		if (_version.supports_negotiable_signature_algorithms())
		{
			Vector!string hashes = policy.allowed_signature_hashes();
			Vector!string sigs = policy.allowed_signature_methods();
			
			for (size_t i = 0; i != hashes.length; ++i)
				for (size_t j = 0; j != sigs.length; ++j)
					m_supported_algos.push_back(Pair(hashes[i], sigs[j]));
		}
		
		hash.update(io.send(this));
	}

	/**
	* Deserialize a Certificate Request message
	*/
	this(in Vector!ubyte buf,
	     Protocol_Version _version)
	{
		if (buf.length < 4)
			throw new Decoding_Error("Certificate_Req: Bad certificate request");
		
		TLS_Data_Reader reader("CertificateRequest", buf);
		
		Vector!ubyte cert_type_codes = reader.get_range_vector!ubyte(1, 1, 255);
		
		for (size_t i = 0; i != cert_type_codes.length; ++i)
		{
			const string cert_type_name = cert_type_code_to_name(cert_type_codes[i]);
			
			if (cert_type_name == "") // something we don't know
				continue;
			
			m_cert_key_types.push_back(cert_type_name);
		}
		
		if (_version.supports_negotiable_signature_algorithms())
		{
			Vector!ubyte sig_hash_algs = reader.get_range_vector!ubyte(2, 2, 65534);
			
			if (sig_hash_algs.length % 2 != 0)
				throw new Decoding_Error("Bad length for signature IDs in certificate request");
			
			for (size_t i = 0; i != sig_hash_algs.length; i += 2)
			{
				string hash = Signature_Algorithms.hash_algo_name(sig_hash_algs[i]);
				string sig = Signature_Algorithms.sig_algo_name(sig_hash_algs[i+1]);
				m_supported_algos.push_back(Pair(hash, sig));
			}
		}
		
		const ushort purported_size = reader.get_ushort();
		
		if (reader.remaining_bytes() != purported_size)
			throw new Decoding_Error("Inconsistent length in certificate request");
		
		while(reader.has_remaining())
		{
			Vector!ubyte name_bits = reader.get_range_vector!ubyte(2, 0, 65535);
			
			BER_Decoder decoder(&name_bits[0], name_bits.length);
			X509_DN name;
			decoder.decode(name);
			m_names.push_back(name);
		}
	}

private:

	/**
	* Serialize a Certificate Request message
	*/
	override Vector!ubyte serialize() const
	{
		Vector!ubyte buf;
		
		Vector!ubyte cert_types;
		
		for (size_t i = 0; i != m_cert_key_types.length; ++i)
			cert_types.push_back(cert_type_name_to_code(m_cert_key_types[i]));
		
		append_tls_length_value(buf, cert_types, 1);
		
		if (!m_supported_algos.empty())
			buf += Signature_Algorithms(m_supported_algos).serialize();
		
		Vector!ubyte encoded_names;
		
		for (size_t i = 0; i != m_names.length; ++i)
		{
			DER_Encoder encoder = DER_Encoder();
			encoder.encode(m_names[i]);
			
			append_tls_length_value(encoded_names, encoder.get_contents(), 2);
		}
		
		append_tls_length_value(buf, encoded_names, 2);
		
		return buf;
	}

	Vector!X509_DN m_names;
	Vector!string m_cert_key_types;

	Vector!( Pair!(string, string)  ) m_supported_algos;
};

/**
* Certificate Verify Message
*/
class Certificate_Verify : Handshake_Message
{
public:
	override Handshake_Type type() const { return CERTIFICATE_VERIFY; }

	/**
	* Check the signature on a certificate verify message
	* @param cert the purported certificate
	* @param state the handshake state
	*/
	bool verify(const X509_Certificate cert,
	            const Handshake_State state) const
	{
		Unique!Public_Key key = cert.subject_public_key();
		
		Pair!(string, Signature_Format) format =
			state.understand_sig_format(*key, m_hash_algo, m_sig_algo, true);
		
		PK_Verifier verifier = PK_Verifier(*key, format.first, format.second);
		if (state._version() == Protocol_Version.SSL_V3)
		{
			SafeVector!ubyte md5_sha = state.hash().final_ssl3(
				state.session_keys().master_secret());
			
			return verifier.verify_message(&md5_sha[16], md5_sha.length-16,
			&m_signature[0], m_signature.length);
		}
		
		return verifier.verify_message(state.hash().get_contents(), m_signature);
	}

	/*
	* Create a new Certificate Verify message
	*/
	this(Handshake_IO io,
	     Handshake_State state,
	     const Policy policy,
	     RandomNumberGenerator rng,
	     const Private_Key priv_key)
	{
		BOTAN_ASSERT_NONNULL(priv_key);
		
		Pair!(string, Signature_Format) format =
			state.choose_sig_format(*priv_key, m_hash_algo, m_sig_algo, true, policy);
		
		PK_Signer signer = PK_Signer(*priv_key, format.first, format.second);
		
		if (state._version() == Protocol_Version.SSL_V3)
		{
			SafeVector!ubyte md5_sha = state.hash().final_ssl3(
				state.session_keys().master_secret());
			
			if (priv_key.algo_name == "DSA")
				m_signature = signer.sign_message(&md5_sha[16], md5_sha.length-16, rng);
			else
				m_signature = signer.sign_message(md5_sha, rng);
		}
		else
		{
			m_signature = signer.sign_message(state.hash().get_contents(), rng);
		}
		
		state.hash().update(io.send(this));
	}

	/*
	* Deserialize a Certificate Verify message
	*/
	this(in Vector!ubyte buf,
	     Protocol_Version _version)
	{
		TLS_Data_Reader reader = TLS_Data_Reader("CertificateVerify", buf);
		
		if (_version.supports_negotiable_signature_algorithms())
		{
			m_hash_algo = Signature_Algorithms.hash_algo_name(reader.get_byte());
			m_sig_algo = Signature_Algorithms.sig_algo_name(reader.get_byte());
		}
		
		m_signature = reader.get_range!ubyte(2, 0, 65535);
	}
private:
	/*
	* Serialize a Certificate Verify message
	*/
	override Vector!ubyte serialize() const
	{
		Vector!ubyte buf;
		
		if (m_hash_algo != "" && m_sig_algo != "")
		{
			buf.push_back(Signature_Algorithms.hash_algo_code(m_hash_algo));
			buf.push_back(Signature_Algorithms.sig_algo_code(m_sig_algo));
		}
		
		const ushort sig_len = m_signature.length;
		buf.push_back(get_byte(0, sig_len));
		buf.push_back(get_byte(1, sig_len));
		buf += m_signature;
		
		return buf;
	}

	string m_sig_algo; // sig algo used to create signature
	string m_hash_algo; // hash used to create signature
	Vector!ubyte m_signature;
};

/**
* Finished Message
*/
class Finished : Handshake_Message
{
public:
	override Handshake_Type type() const { return FINISHED; }

	Vector!ubyte verify_data() const
	{ return m_verification_data; }

	/*
	* Verify a Finished message
	*/
	bool verify(in Handshake_State state,
	            Connection_Side side) const
	{
		return (m_verification_data == finished_compute_verify(state, side));
	}

	/*
	* Create a new Finished message
	*/
	this(Handshake_IO io,
	     Handshake_State state,
	     Connection_Side side)
	{
		m_verification_data = finished_compute_verify(state, side);
		state.hash().update(io.send(this));
	}

	/*
	* Deserialize a Finished message
	*/
	this(in Vector!ubyte buf)
	{
		m_verification_data = buf;
	}
private:
	/*
	* Serialize a Finished message
	*/
	override Vector!ubyte serialize() const
	{
		return m_verification_data;
	}
	
	Vector!ubyte serialize() const;

	Vector!ubyte m_verification_data;
};

/**
* Hello Request Message
*/
class Hello_Request : Handshake_Message
{
public:
	override Handshake_Type type() const { return HELLO_REQUEST; }

	/*
	* Create a new Hello Request message
	*/
	this(Handshake_IO io)
	{
		io.send(this);
	}

	/*
	* Deserialize a Hello Request message
	*/
	this(in Vector!ubyte buf)
	{
		if (buf.length)
			throw new Decoding_Error("Bad Hello_Request, has non-zero size");
	}
private:
	/*
	* Serialize a Hello Request message
	*/
	Vector!ubyte serialize() const
	{
		return Vector!ubyte();
	}
};

/**
* Server Key Exchange Message
*/
class Server_Key_Exchange : Handshake_Message
{
public:
	override Handshake_Type type() const { return SERVER_KEX; }

	const Vector!ubyte params() const { return m_params; }

	/**
	* Verify a Server Key Exchange message
	*/
	bool verify(in Public_Key server_key,
	            const Handshake_State state) const
	{
		Pair!(string, Signature_Format) format =
			state.understand_sig_format(server_key, m_hash_algo, m_sig_algo, false);
		
		PK_Verifier verifier = PK_Verifier(server_key, format.first, format.second);
		verifier.update(state.client_hello().random());
		verifier.update(state.server_hello().random());
		verifier.update(params());
		
		return verifier.check_signature(m_signature);
	}

	// Only valid for certain kex types
	const Private_Key server_kex_key() const
	{
		BOTAN_ASSERT_NONNULL(m_kex_key);
		return *m_kex_key;
	}

	// Only valid for SRP negotiation
	SRP6_Server_Session server_srp_params() const
	{
		BOTAN_ASSERT_NONNULL(m_srp_params);
		return m_srp_params;
	}

	/**
	* Deserialize a Server Key Exchange message
	*/
	this(in Vector!ubyte buf,
	     in string kex_algo,
	     in string sig_algo,
	     Protocol_Version _version) 
	{
		m_kex_key = null;
		m_srp_params = null;
		if (buf.length < 6)
			throw new Decoding_Error("Server_Key_Exchange: Packet corrupted");
		
		TLS_Data_Reader reader = TLS_Data_Reader("ServerKeyExchange", buf);
		
		/*
		* We really are just serializing things back to what they were
		* before, but unfortunately to know where the signature is we need
		* to be able to parse the whole thing anyway.
		*/
		
		if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
		{
			const string identity_hint = reader.get_string(2, 0, 65535);
			append_tls_length_value(m_params, identity_hint, 2);
		}
		
		if (kex_algo == "DH" || kex_algo == "DHE_PSK")
		{
			// 3 bigints, DH p, g, Y
			
			for (size_t i = 0; i != 3; ++i)
			{
				BigInt v = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
				append_tls_length_value(m_params, BigInt.encode(v), 2);
			}
		}
		else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
		{
			const ubyte curve_type = reader.get_byte();
			
			if (curve_type != 3)
				throw new Decoding_Error("Server_Key_Exchange: Server sent non-named ECC curve");
			
			const ushort curve_id = reader.get_ushort();
			
			const string name = Supported_Elliptic_Curves::curve_id_to_name(curve_id);
			
			Vector!ubyte ecdh_key = reader.get_range!ubyte(1, 1, 255);
			
			if (name == "")
				throw new Decoding_Error("Server_Key_Exchange: Server sent unknown named curve " ~
				                         std.conv.to!string(curve_id));
			
			m_params.push_back(curve_type);
			m_params.push_back(get_byte(0, curve_id));
			m_params.push_back(get_byte(1, curve_id));
			append_tls_length_value(m_params, ecdh_key, 1);
		}
		else if (kex_algo == "SRP_SHA")
		{
			// 2 bigints (N,g) then salt, then server B
			
			const BigInt N = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
			const BigInt g = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
			Vector!ubyte salt = reader.get_range!ubyte(1, 1, 255);
			const BigInt B = BigInt.decode(reader.get_range!ubyte(2, 1, 65535));
			
			append_tls_length_value(m_params, BigInt.encode(N), 2);
			append_tls_length_value(m_params, BigInt.encode(g), 2);
			append_tls_length_value(m_params, salt, 1);
			append_tls_length_value(m_params, BigInt.encode(B), 2);
		}
		else if (kex_algo != "PSK")
				throw new Decoding_Error("Server_Key_Exchange: Unsupported kex type " ~ kex_algo);
		
		if (sig_algo != "")
		{
			if (_version.supports_negotiable_signature_algorithms())
			{
				m_hash_algo = Signature_Algorithms.hash_algo_name(reader.get_byte());
				m_sig_algo = Signature_Algorithms.sig_algo_name(reader.get_byte());
			}
			
			m_signature = reader.get_range!ubyte(2, 0, 65535);
		}
		
		reader.assert_done();
	}

	/**
	* Create a new Server Key Exchange message
	*/
	this(Handshake_IO io,
	     Handshake_State state,
	     const Policy policy,
	     Credentials_Manager creds,
	     RandomNumberGenerator rng,
	     const Private_Key signing_key = null)
	{
		const string hostname = state.client_hello().sni_hostname();
		const string kex_algo = state.ciphersuite().kex_algo();
		
		if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
		{
			string identity_hint =
				creds.psk_identity_hint("tls-server", hostname);
			
			append_tls_length_value(m_params, identity_hint, 2);
		}
		
		if (kex_algo == "DH" || kex_algo == "DHE_PSK")
		{
			Unique!DH_PrivateKey dh = new DH_PrivateKey(rng, policy.dh_group());
			
			append_tls_length_value(m_params, BigInt.encode(dh.get_domain().get_p()), 2);
			append_tls_length_value(m_params, BigInt.encode(dh.get_domain().get_g()), 2);
			append_tls_length_value(m_params, dh.public_value(), 2);
			m_kex_key = dh.release();
		}
		else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
		{
			const Vector!string curves =
				state.client_hello().supported_ecc_curves();
			
			if (curves.empty())
				throw new Internal_Error("Client sent no ECC extension but we negotiated ECDH");
			
			const string curve_name = policy.choose_curve(curves);
			
			if (curve_name == "")
				throw new TLS_Exception(Alert.HANDSHAKE_FAILURE,
				                        "Could not agree on an ECC curve with the client");
			
			EC_Group ec_group(curve_name);
			
			Unique!ECDH_PrivateKey ecdh = new ECDH_PrivateKey(rng, ec_group);
			
			const string ecdh_domain_oid = ecdh.domain().get_oid();
			const string domain = oids.lookup(OID(ecdh_domain_oid));
			
			if (domain == "")
				throw new Internal_Error("Could not find name of ECDH domain " ~ ecdh_domain_oid);
			
			const ushort named_curve_id = Supported_Elliptic_Curves::name_to_curve_id(domainput);
			
			m_params.push_back(3); // named curve
			m_params.push_back(get_byte(0, named_curve_id));
			m_params.push_back(get_byte(1, named_curve_id));
			
			append_tls_length_value(m_params, ecdh.public_value(), 1);
			
			m_kex_key = ecdh.release();
		}
		else if (kex_algo == "SRP_SHA")
		{
			const string srp_identifier = state.client_hello().srp_identifier();
			
			string group_id;
			BigInt v;
			Vector!ubyte salt;
			
			const bool found = creds.srp_verifier("tls-server", hostname,
			                                      srp_identifier,
			                                      group_id, v, salt,
			                                      policy.hide_unknown_users());
			
			if (!found)
				throw new TLS_Exception(Alert.UNKNOWN_PSK_IDENTITY,
				                        "Unknown SRP user " ~ srp_identifier);
			
			m_srp_params = new SRP6_Server_Session;
			
			BigInt B = m_srp_params.step1(v, group_id,
			                              "SHA-1", rng);
			
			DL_Group group = DL_Group(group_id);
			
			append_tls_length_value(m_params, BigInt.encode(group.get_p()), 2);
			append_tls_length_value(m_params, BigInt.encode(group.get_g()), 2);
			append_tls_length_value(m_params, salt, 1);
			append_tls_length_value(m_params, BigInt.encode(B), 2);
		}
		else if (kex_algo != "PSK")
			throw new Internal_Error("Server_Key_Exchange: Unknown kex type " ~ kex_algo);
		
		if (state.ciphersuite().sig_algo() != "")
		{
			assert(signing_key, "Signing key was set");
			
			Pair!(string, Signature_Format) format =
				state.choose_sig_format(signing_key, m_hash_algo, m_sig_algo, false, policy);
			
			PK_Signer signer = PK_Signer(signing_key, format.first, format.second);
			
			signer.update(state.client_hello().random());
			signer.update(state.server_hello().random());
			signer.update(params());
			m_signature = signer.signature(rng);
		}
		
		state.hash().update(io.send(this));
	}


	~this() {}
private:
	/**
	* Serialize a Server Key Exchange message
	*/
	override Vector!ubyte serialize() const
	{
		Vector!ubyte buf = params();
		
		if (m_signature.length)
		{
			// This should be an explicit version check
			if (m_hash_algo != "" && m_sig_algo != "")
			{
				buf.push_back(Signature_Algorithms.hash_algo_code(m_hash_algo));
				buf.push_back(Signature_Algorithms.sig_algo_code(m_sig_algo));
			}
			
			append_tls_length_value(buf, m_signature, 2);
		}
		
		return buf;
	}

	Unique!Private_Key m_kex_key;
	Unique!SRP6_Server_Session m_srp_params;

	Vector!ubyte m_params;

	string m_sig_algo; // sig algo used to create signature
	string m_hash_algo; // hash used to create signature
	Vector!ubyte m_signature;
};

/**
* Server Hello Done Message
*/
class Server_Hello_Done : Handshake_Message
{
public:
	override Handshake_Type type() const { return SERVER_HELLO_DONE; }

	/*
	* Create a new Server Hello Done message
	*/
	this(Handshake_IO io,
	     Handshake_Hash hash)
	{
		hash.update(io.send(this));
	}

	/*
	* Deserialize a Server Hello Done message
	*/
	this(in Vector!ubyte buf)
	{
		if (buf.length)
			throw new Decoding_Error("Server_Hello_Done: Must be empty, and is not");
	}
private:
	/*
	* Serialize a Server Hello Done message
	*/
	override Vector!ubyte serialize() const
	{
		return Vector!ubyte();
	}
};

/**
* Next Protocol Message
*/
class Next_Protocol : Handshake_Message
{
public:
	override Handshake_Type type() const { return NEXT_PROTOCOL; }

	string protocol() const { return m_protocol; }

	this(in Vector!ubyte buf)
	{
		TLS_Data_Reader reader = TLS_Data_Reader("NextProtocol", buf);
		
		m_protocol = reader.get_string(1, 0, 255);
		
		reader.get_range_vector!ubyte(1, 0, 255); // padding, ignored
	}

	this(Handshake_IO io,
	     Handshake_Hash hash,
	     in string protocol)
	{
		hash.update(io.send(this));
		m_protocol = protocol;
	}

private:

	override Vector!ubyte serialize() const
	{
		Vector!ubyte buf;
		
		append_tls_length_value(buf,
		                        cast(const ubyte*)(m_protocol.ptr),
		                        m_protocol.length,
		                        1);
		
		const ubyte padding_len = 32 - ((m_protocol.length + 2) % 32);
		
		buf.push_back(padding_len);
		
		for (size_t i = 0; i != padding_len; ++i)
			buf.push_back(0);
		
		return buf;
	}

	string m_protocol;
};

/**
* New Session Ticket Message
*/
class New_Session_Ticket : Handshake_Message
{
public:
	override Handshake_Type type() const { return NEW_SESSION_TICKET; }

	uint ticket_lifetime_hint() const { return m_ticket_lifetime_hint; }
	const Vector!ubyte ticket() const { return m_ticket; }

	this(Handshake_IO io,
	     Handshake_Hash hash,
	     in Vector!ubyte ticket,
	     Duration lifetime) 
		
	{	m_ticket_lifetime_hint = lifetime;
		m_ticket = ticket;
		hash.update = io.send(this);
	}

	this(in Vector!ubyte buf)
	{
		if (buf.length < 6)
			throw new Decoding_Error("Session ticket message too short to be valid");
		
		TLS_Data_Reader reader = TLS_Data_Reader("SessionTicket", buf);
		
		m_ticket_lifetime_hint = reader.get_uint();
		m_ticket = reader.get_range!ubyte(2, 0, 65535);
	}

	this(Handshake_IO io,
	     Handshake_Hash hash)
	{
		hash.update(io.send(this));
	}

private:
	override Vector!ubyte serialize() const
	{
		Vector!ubyte buf = Vector!ubyte(4);
		store_be(m_ticket_lifetime_hint.seconds, &buf[0]);
		append_tls_length_value(buf, m_ticket, 2);
		return buf;
	}

	Duration m_ticket_lifetime_hint;
	Vector!ubyte m_ticket;
};

/**
* Change Cipher Spec
*/
class Change_Cipher_Spec : Handshake_Message
{
public:
	override Handshake_Type type() const { return HANDSHAKE_CCS; }

	override Vector!ubyte serialize() const
	{ return Vector!ubyte(1, 1); }
};


private:

string cert_type_code_to_name(ubyte code)
{
	switch(code)
	{
		case 1:
			return "RSA";
		case 2:
			return "DSA";
		case 64:
			return "ECDSA";
		default:
			return ""; // DH or something else
	}
}

ubyte cert_type_name_to_code(in string name)
{
	if (name == "RSA")
		return 1;
	if (name == "DSA")
		return 2;
	if (name == "ECDSA")
		return 64;
	
	throw new Invalid_Argument("Unknown cert type " ~ name);
}


SafeVector!ubyte strip_leading_zeros(in SafeVector!ubyte input)
{
	size_t leading_zeros = 0;
	
	for (size_t i = 0; i != input.length; ++i)
	{
		if (input[i] != 0)
			break;
		++leading_zeros;
	}
	
	SafeVector!ubyte output = SafeVector!ubyte(&input[leading_zeros],
	&input[input.length]);
	return output;
}


/*
* Compute the verify_data
*/
Vector!ubyte finished_compute_verify(in Handshake_State state,
                                     Connection_Side side)
{
	if (state._version() == Protocol_Version.SSL_V3)
	{
		const(ubyte)[] SSL_CLIENT_LABEL = { 0x43, 0x4C, 0x4E, 0x54 };
		const(ubyte)[] SSL_SERVER_LABEL = { 0x53, 0x52, 0x56, 0x52 };
		
		Handshake_Hash hash = state.hash(); // don't modify state
		
		Vector!ubyte ssl3_finished;
		
		if (side == CLIENT)
			hash.update(SSL_CLIENT_LABEL, (SSL_CLIENT_LABEL).sizeof);
		else
			hash.update(SSL_SERVER_LABEL, (SSL_SERVER_LABEL).sizeof);
		
		return unlock(hash.final_ssl3(state.session_keys().master_secret()));
	}
	else
	{
		const(ubyte)[] TLS_CLIENT_LABEL = {
			0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x69, 0x6E, 0x69,
			0x73, 0x68, 0x65, 0x64 };
		
		const(ubyte)[] TLS_SERVER_LABEL = {
			0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6E, 0x69,
			0x73, 0x68, 0x65, 0x64 };
		
		Unique!KDF prf = state.protocol_specific_prf();
		
		Vector!ubyte input;
		if (side == CLIENT)
			input += Pair(TLS_CLIENT_LABEL, (TLS_CLIENT_LABEL).sizeof);
		else
			input += Pair(TLS_SERVER_LABEL, (TLS_SERVER_LABEL).sizeof);
		
		input += state.hash().flushInto(state._version(), state.ciphersuite().prf_algo());
		
		return unlock(prf.derive_key(12, state.session_keys().master_secret(), input));
	}
}

Vector!ubyte make_hello_random(RandomNumberGenerator rng)
{
	Vector!ubyte buf = Vector!ubyte(32);
	
	const uint time32 = cast(uint)(Clock.currTime().toUnixTime);
	
	store_be(time32, &buf[0]);
	rng.randomize(&buf[4], buf.length - 4);
	return buf;
}