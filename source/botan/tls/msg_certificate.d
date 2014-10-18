/*
* Certificate Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_messages;
import botan.internal.tls_reader;
import botan.internal.tls_extensions;
import botan.internal.tls_handshake_io;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.loadstor;
namespace TLS {

/**
* Create a new Certificate message
*/
Certificate::Certificate(Handshake_IO& io,
								 Handshake_Hash& hash,
								 const Vector!( X509_Certificate )& cert_list) :
	m_certs(cert_list)
{
	hash.update(io.send(*this));
}

/**
* Deserialize a Certificate message
*/
Certificate::Certificate(in Vector!ubyte buf)
{
	if (buf.size() < 3)
		throw new Decoding_Error("Certificate: Message malformed");

	const size_t total_size = make_uint(0, buf[0], buf[1], buf[2]);

	if (total_size != buf.size() - 3)
		throw new Decoding_Error("Certificate: Message malformed");

	const ubyte* certs = &buf[3];

	while(size_t remaining_bytes = &buf[buf.size()] - certs)
	{
		if (remaining_bytes < 3)
			throw new Decoding_Error("Certificate: Message malformed");

		const size_t cert_size = make_uint(0, certs[0], certs[1], certs[2]);

		if (remaining_bytes < (3 + cert_size))
			throw new Decoding_Error("Certificate: Message malformed");

		DataSource_Memory cert_buf = new DataSource_Memory(&certs[3], cert_size);
			scope(exit) delete cert_buf;
		m_certs.push_back(X509_Certificate(cert_buf));

		certs += cert_size + 3;
	}
}

/**
* Serialize a Certificate message
*/
Vector!ubyte Certificate::serialize() const
{
	Vector!ubyte buf(3);

	for (size_t i = 0; i != m_certs.size(); ++i)
	{
		Vector!ubyte raw_cert = m_certs[i].BER_encode();
		const size_t cert_size = raw_cert.size();
		for (size_t i = 0; i != 3; ++i)
			buf.push_back(get_byte<uint>(i+1, cert_size));
		buf += raw_cert;
	}

	const size_t buf_size = buf.size() - 3;
	for (size_t i = 0; i != 3; ++i)
		buf[i] = get_byte<uint>(i+1, buf_size);

	return buf;
}

}

}
