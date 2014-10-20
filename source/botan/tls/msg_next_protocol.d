/*
* Next Protocol Negotiation
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_messages;
import botan.tls.tls_extensions;
import botan.tls.tls_reader;
import botan.internal.tls_handshake_io;


Next_Protocol::Next_Protocol(Handshake_IO& io,
									  Handshake_Hash& hash,
									  in string protocol) :
	m_protocol(protocol)
{
	hash.update(io.send(*this));
}

Next_Protocol::Next_Protocol(in Vector!ubyte buf)
{
	TLS_Data_Reader reader("NextProtocol", buf);

	m_protocol = reader.get_string(1, 0, 255);

	reader.get_range_vector!ubyte(1, 0, 255); // padding, ignored
}

Vector!ubyte Next_Protocol::serialize() const
{
	Vector!ubyte buf;

	append_tls_length_value(buf,
									cast(const ubyte*)(m_protocol.data()),
									m_protocol.length,
									1);

	const ubyte padding_len = 32 - ((m_protocol.length + 2) % 32);

	buf.push_back(padding_len);

	for (size_t i = 0; i != padding_len; ++i)
		buf.push_back(0);

	return buf;
}

}

}