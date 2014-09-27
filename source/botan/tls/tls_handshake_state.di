/*
* TLS Handshake State
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.internal.tls_handshake_hash;
import botan.internal.tls_handshake_io;
import botan.internal.tls_session_key;
import botan.tls_ciphersuite;
import botan.tls_exceptn;
import botan.tls_handshake_msg;
import botan.pk_keys;
import botan.pubkey;
import functional;
class KDF;

namespace TLS {

class Policy;

class Hello_Verify_Request;
class Client_Hello;
class Server_Hello;
class Certificate;
class Server_Key_Exchange;
class Certificate_Req;
class Server_Hello_Done;
class Certificate;
class Client_Key_Exchange;
class Certificate_Verify;
class Next_Protocol;
class New_Session_Ticket;
class Finished;

/**
* SSL/TLS Handshake State
*/
class Handshake_State
{
	public:
		Handshake_State(Handshake_IO io,
							 void (const Handshake_Message) msg_callback = null);

		abstract ~Handshake_State();

		Handshake_State(in Handshake_State);
		Handshake_State& operator=(in Handshake_State);

		Handshake_IO& handshake_io() { return *m_handshake_io; }

		/**
		* Return true iff we have received a particular message already
		* @param msg_type the message type
		*/
		bool received_handshake_msg(Handshake_Type msg_type) const;

		/**
		* Confirm that we were expecting this message type
		* @param msg_type the message type
		*/
		void confirm_transition_to(Handshake_Type msg_type);

		/**
		* Record that we are expecting a particular message type next
		* @param msg_type the message type
		*/
		void set_expected_next(Handshake_Type msg_type);

		Pair!(Handshake_Type, Vector!( byte) )
			get_next_handshake_msg();

		Vector!( byte ) session_ticket() const;

		Pair!(string, Signature_Format)
			understand_sig_format(in Public_Key key,
										 string hash_algo,
										 string sig_algo,
										 bool for_client_auth) const;

		Pair!(string, Signature_Format)
			choose_sig_format(in Private_Key key,
									ref string hash_algo,
									ref string sig_algo,
									bool for_client_auth,
									in Policy policy) const;

		string srp_identifier() const;

		KDF* protocol_specific_prf() const;

		Protocol_Version _version() const { return m_version; }

		void set_version(in Protocol_Version _version);

		void hello_verify_request(in Hello_Verify_Request hello_verify);

		void client_hello(Client_Hello client_hello);
		void server_hello(Server_Hello server_hello);
		void server_certs(Certificate server_certs);
		void server_kex(Server_Key_Exchange server_kex);
		void cert_req(Certificate_Req cert_req);
		void server_hello_done(Server_Hello_Done server_hello_done);
		void client_certs(Certificate client_certs);
		void client_kex(Client_Key_Exchange client_kex);
		void client_verify(Certificate_Verify client_verify);
		void next_protocol(Next_Protocol next_protocol);
		void new_session_ticket(New_Session_Ticket new_session_ticket);
		void server_finished(Finished server_finished);
		void client_finished(Finished client_finished);

		const Client_Hello client_hello() const
		{ return m_client_hello.get(); }

		const Server_Hello server_hello() const
		{ return m_server_hello.get(); }

		const Certificate server_certs() const
		{ return m_server_certs.get(); }

		const Server_Key_Exchange server_kex() const
		{ return m_server_kex.get(); }

		const Certificate_Req cert_req() const
		{ return m_cert_req.get(); }

		const Server_Hello_Done server_hello_done() const
		{ return m_server_hello_done.get(); }

		const Certificate client_certs() const
		{ return m_client_certs.get(); }

		const Client_Key_Exchange client_kex() const
		{ return m_client_kex.get(); }

		const Certificate_Verify client_verify() const
		{ return m_client_verify.get(); }

		const Next_Protocol next_protocol() const
		{ return m_next_protocol.get(); }

		const New_Session_Ticket new_session_ticket() const
		{ return m_new_session_ticket.get(); }

		const Finished server_finished() const
		{ return m_server_finished.get(); }

		const Finished client_finished() const
		{ return m_client_finished.get(); }

		const Ciphersuite ciphersuite() const { return m_ciphersuite; }

		const Session_Keys session_keys() const { return m_session_keys; }

		void compute_session_keys();

		void compute_session_keys(in SafeVector!byte resume_master_secret);

		Handshake_Hash hash() { return m_handshake_hash; }

		const Handshake_Hash hash() const { return m_handshake_hash; }

		void note_message(in Handshake_Message msg)
		{
			if (m_msg_callback)
				m_msg_callback(msg);
		}

	private:

		void delegate(const Handshake_Message) m_msg_callback;

		Unique!Handshake_IO m_handshake_io;

		uint m_hand_expecting_mask = 0;
		uint m_hand_received_mask = 0;
		Protocol_Version m_version;
		Ciphersuite m_ciphersuite;
		Session_Keys m_session_keys;
		Handshake_Hash m_handshake_hash;

		Unique!Client_Hello m_client_hello;
		Unique!Server_Hello m_server_hello;
		Unique!Certificate m_server_certs;
		Unique!Server_Key_Exchange m_server_kex;
		Unique!Certificate_Req m_cert_req;
		Unique!Server_Hello_Done m_server_hello_done;
		Unique!Certificate m_client_certs;
		Unique!Client_Key_Exchange m_client_kex;
		Unique!Certificate_Verify m_client_verify;
		Unique!Next_Protocol m_next_protocol;
		Unique!New_Session_Ticket m_new_session_ticket;
		Unique!Finished m_server_finished;
		Unique!Finished m_client_finished;
};

}