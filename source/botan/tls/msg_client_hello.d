/*
* TLS Hello Request and Client Hello Messages
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/internal/stl_util.h>
#include <chrono>
namespace TLS {

enum {
	TLS_EMPTY_RENEGOTIATION_INFO_SCSV		  = 0x00FF
};

Vector!( byte ) make_hello_random(RandomNumberGenerator& rng)
{
	Vector!( byte ) buf(32);

	const uint time32 = cast(uint)(
		std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

	store_be(time32, &buf[0]);
	rng.randomize(&buf[4], buf.size() - 4);
	return buf;
}

/*
* Create a new Hello Request message
*/
Hello_Request::Hello_Request(Handshake_IO& io)
{
	io.send(*this);
}

/*
* Deserialize a Hello Request message
*/
Hello_Request::Hello_Request(in Vector!byte buf)
{
	if(buf.size())
		throw new Decoding_Error("Bad Hello_Request, has non-zero size");
}

/*
* Serialize a Hello Request message
*/
Vector!( byte ) Hello_Request::serialize() const
{
	return Vector!( byte )();
}

/*
* Create a new Client Hello message
*/
Client_Hello::Client_Hello(Handshake_IO& io,
									Handshake_Hash& hash,
									Protocol_Version _version,
									const Policy& policy,
									RandomNumberGenerator& rng,
									in Vector!byte reneg_info,
									bool next_protocol,
									in string hostname,
									in string srp_identifier) :
	m_version(_version),
	m_random(make_hello_random(rng)),
	m_suites(policy.ciphersuite_list(m_version, (srp_identifier != ""))),
	m_comp_methods(policy.compression())
{
	m_extensions.add(new Renegotiation_Extension(reneg_info));
	m_extensions.add(new SRP_Identifier(srp_identifier));
	m_extensions.add(new Server_Name_Indicator(hostname));
	m_extensions.add(new Session_Ticket());
	m_extensions.add(new Supported_Elliptic_Curves(policy.allowed_ecc_curves()));

	if(policy.negotiate_heartbeat_support())
		m_extensions.add(new Heartbeat_Support_Indicator(true));

	if(m_version.supports_negotiable_signature_algorithms())
		m_extensions.add(new Signature_Algorithms(policy.allowed_signature_hashes(),
																policy.allowed_signature_methods()));

	if(reneg_info.empty() && next_protocol)
		m_extensions.add(new Next_Protocol_Notification());

	hash.update(io.send(*this));
}

/*
* Create a new Client Hello message (session resumption case)
*/
Client_Hello::Client_Hello(Handshake_IO& io,
									Handshake_Hash& hash,
									const Policy& policy,
									RandomNumberGenerator& rng,
									in Vector!byte reneg_info,
									const Session& session,
									bool next_protocol) :
	m_version(session._version()),
	m_session_id(session.session_id()),
	m_random(make_hello_random(rng)),
	m_suites(policy.ciphersuite_list(m_version, (session.srp_identifier() != ""))),
	m_comp_methods(policy.compression())
{
	if(!value_exists(m_suites, session.ciphersuite_code()))
		m_suites.push_back(session.ciphersuite_code());

	if(!value_exists(m_comp_methods, session.compression_method()))
		m_comp_methods.push_back(session.compression_method());

	m_extensions.add(new Renegotiation_Extension(reneg_info));
	m_extensions.add(new SRP_Identifier(session.srp_identifier()));
	m_extensions.add(new Server_Name_Indicator(session.server_info().hostname()));
	m_extensions.add(new Session_Ticket(session.session_ticket()));
	m_extensions.add(new Supported_Elliptic_Curves(policy.allowed_ecc_curves()));

	if(policy.negotiate_heartbeat_support())
		m_extensions.add(new Heartbeat_Support_Indicator(true));

	if(session.fragment_size() != 0)
		m_extensions.add(new Maximum_Fragment_Length(session.fragment_size()));

	if(m_version.supports_negotiable_signature_algorithms())
		m_extensions.add(new Signature_Algorithms(policy.allowed_signature_hashes(),
																policy.allowed_signature_methods()));

	if(reneg_info.empty() && next_protocol)
		m_extensions.add(new Next_Protocol_Notification());

	hash.update(io.send(*this));
}

/*
* Read a counterparty client hello
*/
Client_Hello::Client_Hello(in Vector!byte buf, Handshake_Type type)
{
	if(type == CLIENT_HELLO)
		deserialize(buf);
	else
		deserialize_sslv2(buf);
}

void Client_Hello::update_hello_cookie(in Hello_Verify_Request hello_verify)
{
	if(!m_version.is_datagram_protocol())
		throw new Exception("Cannot use hello cookie with stream protocol");

	m_hello_cookie = hello_verify.cookie();
}

/*
* Serialize a Client Hello message
*/
Vector!( byte ) Client_Hello::serialize() const
{
	Vector!( byte ) buf;

	buf.push_back(m_version.major_version());
	buf.push_back(m_version.minor_version());
	buf += m_random;

	append_tls_length_value(buf, m_session_id, 1);

	if(m_version.is_datagram_protocol())
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

void Client_Hello::deserialize_sslv2(in Vector!byte buf)
{
	if(buf.size() < 12 || buf[0] != 1)
		throw new Decoding_Error("Client_Hello: SSLv2 hello corrupted");

	const size_t cipher_spec_len = make_u16bit(buf[3], buf[4]);
	const size_t m_session_id_len = make_u16bit(buf[5], buf[6]);
	const size_t challenge_len = make_u16bit(buf[7], buf[8]);

	const size_t expected_size =
		(9 + m_session_id_len + cipher_spec_len + challenge_len);

	if(buf.size() != expected_size)
		throw new Decoding_Error("Client_Hello: SSLv2 hello corrupted");

	if(m_session_id_len != 0 || cipher_spec_len % 3 != 0 ||
		(challenge_len < 16 || challenge_len > 32))
	{
		throw new Decoding_Error("Client_Hello: SSLv2 hello corrupted");
	}

	m_version = Protocol_Version(buf[1], buf[2]);

	for(size_t i = 9; i != 9 + cipher_spec_len; i += 3)
	{
		if(buf[i] != 0) // a SSLv2 cipherspec; ignore it
			continue;

		m_suites.push_back(make_u16bit(buf[i+1], buf[i+2]));
	}

	m_random.resize(challenge_len);
	copy_mem(&m_random[0], &buf[9+cipher_spec_len+m_session_id_len], challenge_len);

	if(offered_suite(cast(u16bit)(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
		m_extensions.add(new Renegotiation_Extension());
}

/*
* Deserialize a Client Hello message
*/
void Client_Hello::deserialize(in Vector!byte buf)
{
	if(buf.size() == 0)
		throw new Decoding_Error("Client_Hello: Packet corrupted");

	if(buf.size() < 41)
		throw new Decoding_Error("Client_Hello: Packet corrupted");

	TLS_Data_Reader reader("ClientHello", buf);

	const byte major_version = reader.get_byte();
	const byte minor_version = reader.get_byte();

	m_version = Protocol_Version(major_version, minor_version);

	m_random = reader.get_fixed<byte>(32);

	if(m_version.is_datagram_protocol())
		m_hello_cookie = reader.get_range<byte>(1, 0, 255);

	m_session_id = reader.get_range<byte>(1, 0, 32);

	m_suites = reader.get_range_vector<u16bit>(2, 1, 32767);

	m_comp_methods = reader.get_range_vector<byte>(1, 1, 255);

	m_extensions.deserialize(reader);

	if(offered_suite(cast(u16bit)(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
	{
		if(Renegotiation_Extension* reneg = m_extensions.get<Renegotiation_Extension>())
		{
			if(!reneg->renegotiation_info().empty())
				throw new TLS_Exception(Alert::HANDSHAKE_FAILURE,
										  "Client send renegotiation SCSV and non-empty extension");
		}
		else
		{
			// add fake extension
			m_extensions.add(new Renegotiation_Extension());
		}
	}
}

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(u16bit ciphersuite) const
{
	for(size_t i = 0; i != m_suites.size(); ++i)
		if(m_suites[i] == ciphersuite)
			return true;
	return false;
}

}

}
