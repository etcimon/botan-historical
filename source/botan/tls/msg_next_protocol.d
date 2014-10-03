/*
* Next Protocol Negotiation
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_messages;
import botan.internal.tls_extensions;
import botan.internal.tls_reader;
import botan.internal.tls_handshake_io;
namespace TLS {

Next_Protocol::Next_Protocol(Handshake_IO& io,
									  Handshake_Hash& hash,
									  in string protocol) :
	m_protocol(protocol)
{
	hash.update(io.send(*this));
}

Next_Protocol::Next_Protocol(in Vector!byte buf)
{
	TLS_Data_Reader reader("NextProtocol", buf);

	m_protocol = reader.get_string(1, 0, 255);

	reader.get_range_vector!byte(1, 0, 255); // padding, ignored
}

Vector!byte Next_Protocol::serialize() const
{
	Vector!byte buf;

	append_tls_length_value(buf,
									cast(const byte*)(m_protocol.data()),
									m_protocol.size(),
									1);

	const byte padding_len = 32 - ((m_protocol.size() + 2) % 32);

	buf.push_back(padding_len);

	for (size_t i = 0; i != padding_len; ++i)
		buf.push_back(0);

	return buf;
}

}

}
