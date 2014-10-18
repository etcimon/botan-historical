/*
* Certificate Request Message
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

namespace {

string cert_type_code_to_name(ubyte code)
{
	switch(code)
	{
		case 1:
			return "RSA";
		case 2:
			return "DSA";
		case 64:
			return "ECDSA";
		default:
			return ""; // DH or something else
	}
}

ubyte cert_type_name_to_code(in string name)
{
	if (name == "RSA")
		return 1;
	if (name == "DSA")
		return 2;
	if (name == "ECDSA")
		return 64;

	throw new Invalid_Argument("Unknown cert type " ~ name);
}

}

/**
* Create a new Certificate Request message
*/
Certificate_Req::Certificate_Req(Handshake_IO& io,
											Handshake_Hash& hash,
											const Policy& policy,
											const Vector!( X509_DN )& ca_certs,
											Protocol_Version _version) :
	m_names(ca_certs),
	m_cert_key_types({ "RSA", "DSA", "ECDSA" })
{
	if (_version.supports_negotiable_signature_algorithms())
	{
		Vector!string hashes = policy.allowed_signature_hashes();
		Vector!string sigs = policy.allowed_signature_methods();

		for (size_t i = 0; i != hashes.size(); ++i)
			for (size_t j = 0; j != sigs.size(); ++j)
				m_supported_algos.push_back(Pair(hashes[i], sigs[j]));
	}

	hash.update(io.send(*this));
}

/**
* Deserialize a Certificate Request message
*/
Certificate_Req::Certificate_Req(in Vector!ubyte buf,
											Protocol_Version _version)
{
	if (buf.size() < 4)
		throw new Decoding_Error("Certificate_Req: Bad certificate request");

	TLS_Data_Reader reader("CertificateRequest", buf);

	Vector!ubyte cert_type_codes = reader.get_range_vector!ubyte(1, 1, 255);

	for (size_t i = 0; i != cert_type_codes.size(); ++i)
	{
		const string cert_type_name = cert_type_code_to_name(cert_type_codes[i]);

		if (cert_type_name == "") // something we don't know
			continue;

		m_cert_key_types.push_back(cert_type_name);
	}

	if (_version.supports_negotiable_signature_algorithms())
	{
		Vector!ubyte sig_hash_algs = reader.get_range_vector!ubyte(2, 2, 65534);

		if (sig_hash_algs.size() % 2 != 0)
			throw new Decoding_Error("Bad length for signature IDs in certificate request");

		for (size_t i = 0; i != sig_hash_algs.size(); i += 2)
		{
			string hash = Signature_Algorithms::hash_algo_name(sig_hash_algs[i]);
			string sig = Signature_Algorithms::sig_algo_name(sig_hash_algs[i+1]);
			m_supported_algos.push_back(Pair(hash, sig));
		}
	}

	const ushort purported_size = reader.get_ushort();

	if (reader.remaining_bytes() != purported_size)
		throw new Decoding_Error("Inconsistent length in certificate request");

	while(reader.has_remaining())
	{
		Vector!ubyte name_bits = reader.get_range_vector!ubyte(2, 0, 65535);

		BER_Decoder decoder(&name_bits[0], name_bits.size());
		X509_DN name;
		decoder.decode(name);
		m_names.push_back(name);
	}
}

/**
* Serialize a Certificate Request message
*/
Vector!ubyte Certificate_Req::serialize() const
{
	Vector!ubyte buf;

	Vector!ubyte cert_types;

	for (size_t i = 0; i != m_cert_key_types.size(); ++i)
		cert_types.push_back(cert_type_name_to_code(m_cert_key_types[i]));

	append_tls_length_value(buf, cert_types, 1);

	if (!m_supported_algos.empty())
		buf += Signature_Algorithms(m_supported_algos).serialize();

	Vector!ubyte encoded_names;

	for (size_t i = 0; i != m_names.size(); ++i)
	{
		DER_Encoder encoder = DER_Encoder();
		encoder.encode(m_names[i]);

		append_tls_length_value(encoded_names, encoder.get_contents(), 2);
	}

	append_tls_length_value(buf, encoded_names, 2);

	return buf;
}

}

}
