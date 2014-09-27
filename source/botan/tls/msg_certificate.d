/*
* Certificate Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_handshake_io.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/loadstor.h>
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
Certificate::Certificate(in Vector!byte buf)
{
	if (buf.size() < 3)
		throw new Decoding_Error("Certificate: Message malformed");

	const size_t total_size = make_uint(0, buf[0], buf[1], buf[2]);

	if (total_size != buf.size() - 3)
		throw new Decoding_Error("Certificate: Message malformed");

	const byte* certs = &buf[3];

	while(size_t remaining_bytes = &buf[buf.size()] - certs)
	{
		if (remaining_bytes < 3)
			throw new Decoding_Error("Certificate: Message malformed");

		const size_t cert_size = make_uint(0, certs[0], certs[1], certs[2]);

		if (remaining_bytes < (3 + cert_size))
			throw new Decoding_Error("Certificate: Message malformed");

		DataSource_Memory cert_buf(&certs[3], cert_size);
		m_certs.push_back(X509_Certificate(cert_buf));

		certs += cert_size + 3;
	}
}

/**
* Serialize a Certificate message
*/
Vector!( byte ) Certificate::serialize() const
{
	Vector!( byte ) buf(3);

	for (size_t i = 0; i != m_certs.size(); ++i)
	{
		Vector!( byte ) raw_cert = m_certs[i].BER_encode();
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
