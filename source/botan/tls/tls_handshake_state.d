/*
* TLS Handshaking
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_handshake_state.h>
#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_record.h>
namespace TLS {

namespace {

uint bitmask_for_handshake_type(Handshake_Type type)
{
	switch(type)
	{
		case HELLO_VERIFY_REQUEST:
			return (1 << 0);

		case HELLO_REQUEST:
			return (1 << 1);

		/*
		* Same code point for both client hello styles
		*/
		case CLIENT_HELLO:
		case CLIENT_HELLO_SSLV2:
			return (1 << 2);

		case SERVER_HELLO:
			return (1 << 3);

		case CERTIFICATE:
			return (1 << 4);

		case CERTIFICATE_URL:
			return (1 << 5);

		case CERTIFICATE_STATUS:
			return (1 << 6);

		case SERVER_KEX:
			return (1 << 7);

		case CERTIFICATE_REQUEST:
			return (1 << 8);

		case SERVER_HELLO_DONE:
			return (1 << 9);

		case CERTIFICATE_VERIFY:
			return (1 << 10);

		case CLIENT_KEX:
			return (1 << 11);

		case NEXT_PROTOCOL:
			return (1 << 12);

		case NEW_SESSION_TICKET:
			return (1 << 13);

		case HANDSHAKE_CCS:
			return (1 << 14);

		case FINISHED:
			return (1 << 15);

		// allow explicitly disabling new handshakes
		case HANDSHAKE_NONE:
			return 0;
	}

	throw new Internal_Error("Unknown handshake type " + std::to_string(type));
}

}

/*
* Initialize the SSL/TLS Handshake State
*/
Handshake_State::Handshake_State(Handshake_IO* io,
											void delegate(const Handshake_Message) msg_callback) :
	m_msg_callback(msg_callback),
	m_handshake_io(io),
	m_version(m_handshake_io->initial_record_version())
{
}

Handshake_State::~Handshake_State() {}

void Handshake_State::hello_verify_request(const Hello_Verify_Request hello_verify)
{
	note_message(hello_verify);

	m_client_hello->update_hello_cookie(hello_verify);
	hash().reset();
	hash().update(handshake_io().send(*m_client_hello));
	note_message(*m_client_hello);
}

void Handshake_State::client_hello(Client_Hello* client_hello)
{
	m_client_hello.reset(client_hello);
	note_message(*m_client_hello);
}

void Handshake_State::server_hello(Server_Hello* server_hello)
{
	m_server_hello.reset(server_hello);
	m_ciphersuite = Ciphersuite::by_id(m_server_hello->ciphersuite());
	note_message(*m_server_hello);
}

void Handshake_State::server_certs(Certificate* server_certs)
{
	m_server_certs.reset(server_certs);
	note_message(*m_server_certs);
}

void Handshake_State::server_kex(Server_Key_Exchange* server_kex)
{
	m_server_kex.reset(server_kex);
	note_message(*m_server_kex);
}

void Handshake_State::cert_req(Certificate_Req* cert_req)
{
	m_cert_req.reset(cert_req);
	note_message(*m_cert_req);
}

void Handshake_State::server_hello_done(Server_Hello_Done* server_hello_done)
{
	m_server_hello_done.reset(server_hello_done);
	note_message(*m_server_hello_done);
}

void Handshake_State::client_certs(Certificate* client_certs)
{
	m_client_certs.reset(client_certs);
	note_message(*m_client_certs);
}

void Handshake_State::client_kex(Client_Key_Exchange* client_kex)
{
	m_client_kex.reset(client_kex);
	note_message(*m_client_kex);
}

void Handshake_State::client_verify(Certificate_Verify* client_verify)
{
	m_client_verify.reset(client_verify);
	note_message(*m_client_verify);
}

void Handshake_State::next_protocol(Next_Protocol* next_protocol)
{
	m_next_protocol.reset(next_protocol);
	note_message(*m_next_protocol);
}

void Handshake_State::new_session_ticket(New_Session_Ticket* new_session_ticket)
{
	m_new_session_ticket.reset(new_session_ticket);
	note_message(*m_new_session_ticket);
}

void Handshake_State::server_finished(Finished* server_finished)
{
	m_server_finished.reset(server_finished);
	note_message(*m_server_finished);
}

void Handshake_State::client_finished(Finished* client_finished)
{
	m_client_finished.reset(client_finished);
	note_message(*m_client_finished);
}

void Handshake_State::set_version(in Protocol_Version _version)
{
	m_version = _version;
}

void Handshake_State::compute_session_keys()
{
	m_session_keys = Session_Keys(this, client_kex()->pre_master_secret(), false);
}

void Handshake_State::compute_session_keys(in SafeVector!byte resume_master_secret)
{
	m_session_keys = Session_Keys(this, resume_master_secret, true);
}

void Handshake_State::confirm_transition_to(Handshake_Type handshake_msg)
{
	const uint mask = bitmask_for_handshake_type(handshake_msg);

	m_hand_received_mask |= mask;

	const bool ok = (m_hand_expecting_mask & mask); // overlap?

	if(!ok)
		throw new Unexpected_Message("Unexpected state transition in handshake, got " +
										 std::to_string(handshake_msg) +
										 " expected " + std::to_string(m_hand_expecting_mask) +
										 " received " + std::to_string(m_hand_received_mask));

	/* We don't know what to expect next, so force a call to
		set_expected_next; if it doesn't happen, the next transition
		check will always fail which is what we want.
	*/
	m_hand_expecting_mask = 0;
}

void Handshake_State::set_expected_next(Handshake_Type handshake_msg)
{
	m_hand_expecting_mask |= bitmask_for_handshake_type(handshake_msg);
}

bool Handshake_State::received_handshake_msg(Handshake_Type handshake_msg) const
{
	const uint mask = bitmask_for_handshake_type(handshake_msg);

	return (m_hand_received_mask & mask);
}

Pair!(Handshake_Type, Vector!( byte) )
Handshake_State::get_next_handshake_msg()
{
	const bool expecting_ccs =
		(bitmask_for_handshake_type(HANDSHAKE_CCS) & m_hand_expecting_mask);

	return m_handshake_io->get_next_record(expecting_ccs);
}

string Handshake_State::srp_identifier() const
{
	if(ciphersuite().valid() && ciphersuite().kex_algo() == "SRP_SHA")
		return client_hello()->srp_identifier();

	return "";
}

Vector!( byte ) Handshake_State::session_ticket() const
{
	if(new_session_ticket() && !new_session_ticket()->ticket().empty())
		return new_session_ticket()->ticket();

	return client_hello()->session_ticket();
}

KDF* Handshake_State::protocol_specific_prf() const
{
	if(_version() == Protocol_Version::SSL_V3)
	{
		return get_kdf("SSL3-PRF");
	}
	else if(_version().supports_ciphersuite_specific_prf())
	{
		const string prf_algo = ciphersuite().prf_algo();

		if(prf_algo == "MD5" || prf_algo == "SHA-1")
			return get_kdf("TLS-12-PRF(SHA-256)");

		return get_kdf("TLS-12-PRF(" + prf_algo + ")");
	}
	else
	{
		// TLS v1.0, v1.1 and DTLS v1.0
		return get_kdf("TLS-PRF");
	}

	throw new Internal_Error("Unknown version code " + _version().to_string());
}

namespace {

string choose_hash(in string sig_algo,
								Protocol_Version negotiated_version,
								in Policy policy,
								bool for_client_auth,
								in Client_Hello client_hello,
								in Certificate_Req cert_req)
{
	if(!negotiated_version.supports_negotiable_signature_algorithms())
	{
		if(for_client_auth && negotiated_version == Protocol_Version::SSL_V3)
			return "Raw";

		if(sig_algo == "RSA")
			return "Parallel(MD5,SHA-160)";

		if(sig_algo == "DSA")
			return "SHA-1";

		if(sig_algo == "ECDSA")
			return "SHA-1";

		throw new Internal_Error("Unknown TLS signature algo " + sig_algo);
	}

	const auto supported_algos = for_client_auth ?
		cert_req->supported_algos() :
		client_hello->supported_algos();

	if(!supported_algos.empty())
	{
		const auto hashes = policy.allowed_signature_hashes();

		/*
		* Choose our most preferred hash that the counterparty supports
		* in pairing with the signature algorithm we want to use.
		*/
		for(auto hash : hashes)
		{
			for(auto algo : supported_algos)
			{
				if(algo.first == hash && algo.second == sig_algo)
					return hash;
			}
		}
	}

	// TLS v1.2 default hash if the counterparty sent nothing
	return "SHA-1";
}

}

Pair!(string, Signature_Format)
Handshake_State::choose_sig_format(in Private_Key key,
											 ref string hash_algo_out,
											 ref string sig_algo_out,
											 bool for_client_auth,
											 const Policy policy) const
{
	const string sig_algo = key.algo_name();

	const string hash_algo =
		choose_hash(sig_algo,
						this->_version(),
						policy,
						for_client_auth,
						client_hello(),
						cert_req());

	if(this->_version().supports_negotiable_signature_algorithms())
	{
		hash_algo_out = hash_algo;
		sig_algo_out = sig_algo;
	}

	if(sig_algo == "RSA")
	{
		const string padding = "EMSA3(" + hash_algo + ")";

		return std::make_pair(padding, IEEE_1363);
	}
	else if(sig_algo == "DSA" || sig_algo == "ECDSA")
	{
		const string padding = "EMSA1(" + hash_algo + ")";

		return std::make_pair(padding, DER_SEQUENCE);
	}

	throw new Invalid_Argument(sig_algo + " is invalid/unknown for TLS signatures");
}

Pair!(string, Signature_Format)
Handshake_State::understand_sig_format(const Public_Key key,
													string hash_algo,
													string sig_algo,
													bool for_client_auth) const
{
	const string algo_name = key.algo_name();

	/*
	FIXME: This should check what was sent against the client hello
	preferences, or the certificate request, to ensure it was allowed
	by those restrictions.

	Or not?
	*/

	if(this->_version().supports_negotiable_signature_algorithms())
	{
		if(hash_algo == "")
			throw new Decoding_Error("Counterparty did not send hash/sig IDS");

		if(sig_algo != algo_name)
			throw new Decoding_Error("Counterparty sent inconsistent key and sig types");
	}
	else
	{
		if(hash_algo != "" || sig_algo != "")
			throw new Decoding_Error("Counterparty sent hash/sig IDs with old version");
	}

	if(algo_name == "RSA")
	{
		if(for_client_auth && this->_version() == Protocol_Version::SSL_V3)
		{
			hash_algo = "Raw";
		}
		else if(!this->_version().supports_negotiable_signature_algorithms())
		{
			hash_algo = "Parallel(MD5,SHA-160)";
		}

		const string padding = "EMSA3(" + hash_algo + ")";
		return std::make_pair(padding, IEEE_1363);
	}
	else if(algo_name == "DSA" || algo_name == "ECDSA")
	{
		if(algo_name == "DSA" && for_client_auth && this->_version() == Protocol_Version::SSL_V3)
		{
			hash_algo = "Raw";
		}
		else if(!this->_version().supports_negotiable_signature_algorithms())
		{
			hash_algo = "SHA-1";
		}

		const string padding = "EMSA1(" + hash_algo + ")";

		return std::make_pair(padding, DER_SEQUENCE);
	}

	throw new Invalid_Argument(algo_name + " is invalid/unknown for TLS signatures");
}

}

}
