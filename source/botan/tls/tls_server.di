/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.tls_channel;
import botan.credentials.credentials_manager;
import vector;

/**
* TLS Server
*/
class Server : Channel
{
public:
	/**
	* Server initialization
	*/
	Server(void delegate(in ubyte*) socket_output_fn,
			 void delegate(in ubyte*) data_cb,
			 void delegate(Alert, in ubyte*) alert_cb,
			 bool delegate(const Session) handshake_cb,
			 Session_Manager session_manager,
			 Credentials_Manager creds,
			 const Policy policy,
			 RandomNumberGenerator rng,
			 in string[] protocols = [],
			 size_t reserved_io_buffer_size = 16*1024
		);

	/**
	* Return the protocol notification set by the client (using the
	* NPN extension) for this connection, if any
	*/
	string next_protocol() const { return m_next_protocol; }

private:
	override X509_Certificate[]
		 get_peer_cert_chain(in Handshake_State state) const;

	override void initiate_handshake(Handshake_State& state,
									 bool force_full_renegotiation);

	override void process_handshake_msg(const Handshake_State* active_state,
										Handshake_State& pending_state,
										Handshake_Type type,
										 in Vector!ubyte contents);

	override Handshake_State* new_handshake_state(Handshake_IO* io);

	const Policy& m_policy;
	Credentials_Manager& m_creds;

	Vector!string m_possible_protocols;
	string m_next_protocol;
};