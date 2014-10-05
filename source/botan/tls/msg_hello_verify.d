/*
* DTLS Hello Verify Request
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_messages;
import botan.lookup;
namespace TLS {

Hello_Verify_Request::Hello_Verify_Request(in Vector!ubyte buf)
{
	if (buf.size() < 3)
		throw new Decoding_Error("Hello verify request too small");

	Protocol_Version version(buf[0], buf[1]);

	if (version != Protocol_Version::DTLS_V10 &&
		version != Protocol_Version::DTLS_V12)
	{
		throw new Decoding_Error("Unknown version from server in hello verify request");
	}

	if (cast(size_t)(buf[2]) + 3 != buf.size())
		throw new Decoding_Error("Bad length in hello verify request");

	m_cookie.assign(&buf[3], &buf[buf.size()]);
}

Hello_Verify_Request::Hello_Verify_Request(in Vector!ubyte client_hello_bits,
														 in string client_identity,
														 const SymmetricKey& secret_key)
{
	Unique!MessageAuthenticationCode hmac(get_mac("HMAC(SHA-256)"));
	hmac.set_key(secret_key);

	hmac.update_be(client_hello_bits.size());
	hmac.update(client_hello_bits);
	hmac.update_be(client_identity.size());
	hmac.update(client_identity);

	m_cookie = unlock(hmac.flush());
}

Vector!ubyte Hello_Verify_Request::serialize() const
{
	/* DTLS 1.2 server implementations SHOULD use DTLS version 1.0
		regardless of the version of TLS that is expected to be
		negotiated (RFC 6347, section 4.2.1)
	*/

	Protocol_Version format_version(Protocol_Version::DTLS_V10);

	Vector!ubyte bits;
	bits.push_back(format_version.major_version());
	bits.push_back(format_version.minor_version());
	bits.push_back(cast(ubyte)(m_cookie.size()));
	bits += m_cookie;
	return bits;
}

}

}
