/*
* Session Tickets
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_messages;
import botan.internal.tls_extensions;
import botan.internal.tls_reader;
import botan.internal.tls_handshake_io;
import botan.loadstor;
namespace TLS {

New_Session_Ticket::New_Session_Ticket(Handshake_IO& io,
													Handshake_Hash& hash,
													in Vector!ubyte ticket,
													Duration lifetime) :
	m_ticket_lifetime_hint(lifetime),
	m_ticket(ticket)
{
	hash.update(io.send(*this));
}

New_Session_Ticket::New_Session_Ticket(Handshake_IO& io,
													Handshake_Hash& hash)
{
	hash.update(io.send(*this));
}

New_Session_Ticket::New_Session_Ticket(in Vector!ubyte buf)
{
	if (buf.size() < 6)
		throw new Decoding_Error("Session ticket message too short to be valid");

	TLS_Data_Reader reader("SessionTicket", buf);

	m_ticket_lifetime_hint = reader.get_uint();
	m_ticket = reader.get_range!ubyte(2, 0, 65535);
}

Vector!ubyte New_Session_Ticket::serialize() const
{
	Vector!ubyte buf(4);
	store_be(m_ticket_lifetime_hint.seconds, &buf[0]);
	append_tls_length_value(buf, m_ticket, 2);
	return buf;
}

}

}
