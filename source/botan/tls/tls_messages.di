/*
* TLS Messages
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.internal.tls_handshake_state;
import botan.internal.tls_extensions;
import botan.tls_handshake_msg;
import botan.tls_session;
import botan.tls_policy;
import botan.tls_ciphersuite;
import botan.bigint;
import botan.pkcs8;
import botan.x509cert;
import vector;
import string;
class Credentials_Manager;
class SRP6_Server_Session;

namespace TLS {

class Handshake_IO;

Vector!ubyte make_hello_random(RandomNumberGenerator rng);

/**
* DTLS Hello Verify Request
*/
class Hello_Verify_Request : public Handshake_Message
{
	public:
		Vector!ubyte serialize() const override;
		Handshake_Type type() const override { return HELLO_VERIFY_REQUEST; }

		Vector!ubyte cookie() const { return m_cookie; }

		Hello_Verify_Request(in Vector!ubyte buf);

		Hello_Verify_Request(in Vector!ubyte client_hello_bits,
									in string client_identity,
									const SymmetricKey& secret_key);
	private:
		Vector!ubyte m_cookie;
};

/**
* Client Hello Message
*/
class Client_Hello : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return CLIENT_HELLO; }

		Protocol_Version _version() const { return m_version; }

		in Vector!ubyte random() const { return m_random; }

		in Vector!ubyte session_id() const { return m_session_id; }

		Vector!( ushort ) ciphersuites() const { return m_suites; }

		Vector!ubyte compression_methods() const { return m_comp_methods; }

		bool offered_suite(ushort ciphersuite) const;

		Vector!( Pair!(string, string) ) supported_algos() const
		{
			if (Signature_Algorithms* sigs = m_extensions.get<Signature_Algorithms>())
				return sigs.supported_signature_algorthms();
			return Vector!( Pair!(string, string) )();
		}

		Vector!string supported_ecc_curves() const
		{
			if (Supported_Elliptic_Curves* ecc = m_extensions.get<Supported_Elliptic_Curves>())
				return ecc.curves();
			return Vector!string();
		}

		string sni_hostname() const
		{
			if (Server_Name_Indicator* sni = m_extensions.get<Server_Name_Indicator>())
				return sni.host_name();
			return "";
		}

		string srp_identifier() const
		{
			if (SRP_Identifier* srp = m_extensions.get<SRP_Identifier>())
				return srp.identifier();
			return "";
		}

		bool secure_renegotiation() const
		{
			return m_extensions.get<Renegotiation_Extension>();
		}

		Vector!ubyte renegotiation_info() const
		{
			if (Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
				return reneg.renegotiation_info();
			return Vector!ubyte();
		}

		bool next_protocol_notification() const
		{
			return m_extensions.get<Next_Protocol_Notification>();
		}

		size_t fragment_size() const
		{
			if (Maximum_Fragment_Length* frag = m_extensions.get<Maximum_Fragment_Length>())
				return frag.fragment_size();
			return 0;
		}

		bool supports_session_ticket() const
		{
			return m_extensions.get<Session_Ticket>();
		}

		Vector!ubyte session_ticket() const
		{
			if (Session_Ticket* ticket = m_extensions.get<Session_Ticket>())
				return ticket.contents();
			return Vector!ubyte();
		}

		bool supports_heartbeats() const
		{
			return m_extensions.get<Heartbeat_Support_Indicator>();
		}

		bool peer_can_send_heartbeats() const
		{
			if (Heartbeat_Support_Indicator hb = m_extensions.get<Heartbeat_Support_Indicator>())
				return hb.peer_allowed_to_send();
			return false;
		}

		void update_hello_cookie(in Hello_Verify_Request hello_verify);

		std::set<Handshake_Extension_Type> extension_types() const
		{ return m_extensions.extension_types(); }

		Client_Hello(Handshake_IO io,
						 Handshake_Hash hash,
						 Protocol_Version _version,
						 in Policy policy,
						 RandomNumberGenerator rng,
						 in Vector!ubyte reneg_info,
						 bool next_protocol = false,
						 in string hostname = "",
						 in string srp_identifier = "");

		Client_Hello(Handshake_IO io,
						 Handshake_Hash hash,
						 in Policy policy,
						 RandomNumberGenerator rng,
						 in Vector!ubyte reneg_info,
						 in Session resumed_session,
						 bool next_protocol = false);

		Client_Hello(in Vector!ubyte buf,
						 Handshake_Type type);

	private:
		Vector!ubyte serialize() const override;
		void deserialize(in Vector!ubyte buf);
		void deserialize_sslv2(in Vector!ubyte buf);

		Protocol_Version m_version;
		Vector!ubyte m_session_id;
		Vector!ubyte m_random;
		Vector!( ushort ) m_suites;
		Vector!ubyte m_comp_methods;
		Vector!ubyte m_hello_cookie; // DTLS only

		Extensions m_extensions;
};

/**
* Server Hello Message
*/
class Server_Hello : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return SERVER_HELLO; }

		Protocol_Version _version() const { return m_version; }

		in Vector!ubyte random() const { return m_random; }

		in Vector!ubyte session_id() const { return m_session_id; }

		ushort ciphersuite() const { return m_ciphersuite; }

		ubyte compression_method() const { return m_comp_method; }

		bool secure_renegotiation() const
		{
			return m_extensions.get<Renegotiation_Extension>();
		}

		Vector!ubyte renegotiation_info() const
		{
			if (Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
				return reneg.renegotiation_info();
			return Vector!ubyte();
		}

		bool next_protocol_notification() const
		{
			return m_extensions.get<Next_Protocol_Notification>();
		}

		Vector!string next_protocols() const
		{
			if (Next_Protocol_Notification* npn = m_extensions.get<Next_Protocol_Notification>())
				return npn.protocols();
			return Vector!string();
		}

		size_t fragment_size() const
		{
			if (Maximum_Fragment_Length* frag = m_extensions.get<Maximum_Fragment_Length>())
				return frag.fragment_size();
			return 0;
		}

		bool supports_session_ticket() const
		{
			return m_extensions.get<Session_Ticket>();
		}

		bool supports_heartbeats() const
		{
			return m_extensions.get<Heartbeat_Support_Indicator>();
		}

		bool peer_can_send_heartbeats() const
		{
			if (Heartbeat_Support_Indicator* hb = m_extensions.get<Heartbeat_Support_Indicator>())
				return hb.peer_allowed_to_send();
			return false;
		}

		std::set<Handshake_Extension_Type> extension_types() const
		{ return m_extensions.extension_types(); }

		Server_Hello(Handshake_IO io,
						 Handshake_Hash hash,
						 in Policy policy,
						 in Vector!ubyte session_id,
						 Protocol_Version _version,
						 ushort ciphersuite,
						 ubyte compression,
						 size_t max_fragment_size,
						 bool client_has_secure_renegotiation,
						 in Vector!ubyte reneg_info,
						 bool offer_session_ticket,
						 bool client_has_npn,
						 in Vector!string next_protocols,
						 bool client_has_heartbeat,
						 RandomNumberGenerator rng);

		Server_Hello(in Vector!ubyte buf);
	private:
		Vector!ubyte serialize() const override;

		Protocol_Version m_version;
		Vector!ubyte m_session_id, m_random;
		ushort m_ciphersuite;
		ubyte m_comp_method;

		Extensions m_extensions;
};

/**
* Client Key Exchange Message
*/
class Client_Key_Exchange : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return CLIENT_KEX; }

		in SafeVector!ubyte pre_master_secret() const
		{ return m_pre_master; }

		Client_Key_Exchange(Handshake_IO io,
								  Handshake_State state,
								  in Policy policy,
								  Credentials_Manager& creds,
								  in Public_Key server_public_key,
								  in string hostname,
								  RandomNumberGenerator rng);

		Client_Key_Exchange(in Vector!ubyte buf,
								  in Handshake_State state,
								  in Private_Key server_rsa_kex_key,
								  Credentials_Manager creds,
								  in Policy policy,
								  RandomNumberGenerator rng);

	private:
		Vector!ubyte serialize() const override
		{ return m_key_material; }

		Vector!ubyte m_key_material;
		SafeVector!ubyte m_pre_master;
};

/**
* Certificate Message
*/
class Certificate : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return CERTIFICATE; }
		const Vector!( X509_Certificate )& cert_chain() const { return m_certs; }

		size_t count() const { return m_certs.size(); }
		bool empty() const { return m_certs.empty(); }

		Certificate(Handshake_IO io,
						Handshake_Hash hash,
						const Vector!( X509_Certificate )& certs);

		Certificate(in Vector!ubyte buf);
	private:
		Vector!ubyte serialize() const override;

		Vector!( X509_Certificate ) m_certs;
};

/**
* Certificate Request Message
*/
class Certificate_Req : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return CERTIFICATE_REQUEST; }

		const Vector!string& acceptable_cert_types() const
		{ return m_cert_key_types; }

		Vector!( X509_DN ) acceptable_CAs() const { return m_names; }

		Vector!( Pair!(string, string)  ) supported_algos() const
		{ return m_supported_algos; }

		Certificate_Req(Handshake_IO io,
							 Handshake_Hash hash,
							 in Policy policy,
							 in Vector!( X509_DN ) allowed_cas,
							 Protocol_Version _version);

		Certificate_Req(in Vector!ubyte buf,
							 Protocol_Version _version);
	private:
		Vector!ubyte serialize() const override;

		Vector!( X509_DN ) m_names;
		Vector!string m_cert_key_types;

		Vector!( Pair!(string, string)  ) m_supported_algos;
};

/**
* Certificate Verify Message
*/
class Certificate_Verify : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return CERTIFICATE_VERIFY; }

		/**
		* Check the signature on a certificate verify message
		* @param cert the purported certificate
		* @param state the handshake state
		*/
		bool verify(in X509_Certificate cert,
						in Handshake_State state) const;

		Certificate_Verify(Handshake_IO io,
								 Handshake_State state,
								 in Policy policy,
								 RandomNumberGenerator rng,
								 in Private_Key key);

		Certificate_Verify(in Vector!ubyte buf,
								 Protocol_Version _version);
	private:
		Vector!ubyte serialize() const override;

		string m_sig_algo; // sig algo used to create signature
		string m_hash_algo; // hash used to create signature
		Vector!ubyte m_signature;
};

/**
* Finished Message
*/
class Finished : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return FINISHED; }

		Vector!ubyte verify_data() const
		{ return m_verification_data; }

		bool verify(in Handshake_State state,
						Connection_Side side) const;

		Finished(Handshake_IO io,
					Handshake_State state,
					Connection_Side side);

		Finished(in Vector!ubyte buf);
	private:
		Vector!ubyte serialize() const override;

		Vector!ubyte m_verification_data;
};

/**
* Hello Request Message
*/
class Hello_Request : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return HELLO_REQUEST; }

		Hello_Request(Handshake_IO io);
		Hello_Request(in Vector!ubyte buf);
	private:
		Vector!ubyte serialize() const override;
};

/**
* Server Key Exchange Message
*/
class Server_Key_Exchange : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return SERVER_KEX; }

		in Vector!ubyte params() const { return m_params; }

		bool verify(in Public_Key server_key,
						in Handshake_State state) const;

		// Only valid for certain kex types
		in Private_Key server_kex_key() const;

		// Only valid for SRP negotiation
		SRP6_Server_Session& server_srp_params() const;

		Server_Key_Exchange(Handshake_IO io,
								  Handshake_State state,
								  in Policy policy,
								  Credentials_Manager creds,
								  RandomNumberGenerator rng,
								  in Private_Key signing_key = null);

		Server_Key_Exchange(in Vector!ubyte buf,
								  in string kex_alg,
								  in string sig_alg,
								  Protocol_Version _version);

		~this();
	private:
		Vector!ubyte serialize() const override;

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
class Server_Hello_Done : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return SERVER_HELLO_DONE; }

		Server_Hello_Done(Handshake_IO io, Handshake_Hash& hash);
		Server_Hello_Done(in Vector!ubyte buf);
	private:
		Vector!ubyte serialize() const override;
};

/**
* Next Protocol Message
*/
class Next_Protocol : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return NEXT_PROTOCOL; }

		string protocol() const { return m_protocol; }

		Next_Protocol(Handshake_IO io,
						  Handshake_Hash hash,
						  in string protocol);

		Next_Protocol(in Vector!ubyte buf);
	private:
		Vector!ubyte serialize() const override;

		string m_protocol;
};

/**
* New Session Ticket Message
*/
class New_Session_Ticket : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return NEW_SESSION_TICKET; }

		uint ticket_lifetime_hint() const { return m_ticket_lifetime_hint; }
		in Vector!ubyte ticket() const { return m_ticket; }

		New_Session_Ticket(Handshake_IO io,
								 Handshake_Hash hash,
								 in Vector!ubyte ticket,
								 uint lifetime);

		New_Session_Ticket(Handshake_IO io,
								 Handshake_Hash hash);

		New_Session_Ticket(in Vector!ubyte buf);
	private:
		Vector!ubyte serialize() const override;

		uint m_ticket_lifetime_hint = 0;
		Vector!ubyte m_ticket;
};

/**
* Change Cipher Spec
*/
class Change_Cipher_Spec : public Handshake_Message
{
	public:
		Handshake_Type type() const override { return HANDSHAKE_CCS; }

		Vector!ubyte serialize() const override
		{ return Vector!ubyte(1, 1); }
};

}