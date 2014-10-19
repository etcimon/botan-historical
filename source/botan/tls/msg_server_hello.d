;/*
* TLS Server Hello and Server Hello Done
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_messages;
import botan.internal.tls_reader;
import botan.internal.tls_session_key;
import botan.internal.tls_extensions;
import botan.internal.tls_handshake_io;
import botan.internal.stl_util;
namespace TLS {

/*
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(Handshake_IO& io,
									Handshake_Hash& hash,
									const Policy& policy,
									in Vector!ubyte session_id,
									Protocol_Version ver,
									ushort ciphersuite,
									ubyte compression,
									size_t max_fragment_size,
									bool client_has_secure_renegotiation,
									in Vector!ubyte reneg_info,
									bool offer_session_ticket,
									bool client_has_npn,
									const Vector!string& next_protocols,
									bool client_has_heartbeat,
									RandomNumberGenerator rng) :
	m_version(ver),
	m_session_id(session_id),
	m_random(make_hello_random(rng)),
	m_ciphersuite(ciphersuite),
	m_comp_method(compression)
{
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

	hash.update(io.send(*this));
}

/*
* Deserialize a Server Hello message
*/
Server_Hello::Server_Hello(in Vector!ubyte buf)
{
	if (buf.length < 38)
		throw new Decoding_Error("Server_Hello: Packet corrupted");

	TLS_Data_Reader reader("ServerHello", buf);

	const ubyte major_version = reader.get_byte();
	const ubyte minor_version = reader.get_byte();

	m_version = Protocol_Version(major_version, minor_version);

	m_random = reader.get_fixed<ubyte>(32);

	m_session_id = reader.get_range!ubyte(1, 0, 32);

	m_ciphersuite = reader.get_ushort();

	m_comp_method = reader.get_byte();

	m_extensions.deserialize(reader);
}

/*
* Serialize a Server Hello message
*/
Vector!ubyte Server_Hello::serialize() const
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

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Handshake_IO& io,
												 Handshake_Hash& hash)
{
	hash.update(io.send(*this));
}

/*
* Deserialize a Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(in Vector!ubyte buf)
{
	if (buf.length)
		throw new Decoding_Error("Server_Hello_Done: Must be empty, and is not");
}

/*
* Serialize a Server Hello Done message
*/
Vector!ubyte Server_Hello_Done::serialize() const
{
	return Vector!ubyte();
}

}

}
