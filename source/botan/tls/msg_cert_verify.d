/*
* Certificate Verify Message
* (C) 2004,2006,2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_messages;
import botan.internal.tls_reader;
import botan.internal.tls_extensions;
import botan.internal.tls_handshake_io;
namespace TLS {

/*
* Create a new Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(Handshake_IO& io,
													Handshake_State state,
													const Policy policy,
													RandomNumberGenerator rng,
													const Private_Key priv_key)
{
	BOTAN_ASSERT_NONNULL(priv_key);

	Pair!(string, Signature_Format) format =
		state.choose_sig_format(*priv_key, m_hash_algo, m_sig_algo, true, policy);

	PK_Signer signer(*priv_key, format.first, format.second);

	if (state._version() == Protocol_Version::SSL_V3)
	{
		SafeVector!ubyte md5_sha = state.hash().final_ssl3(
			state.session_keys().master_secret());

		if (priv_key.algo_name() == "DSA")
			m_signature = signer.sign_message(&md5_sha[16], md5_sha.length-16, rng);
		else
			m_signature = signer.sign_message(md5_sha, rng);
	}
	else
	{
		m_signature = signer.sign_message(state.hash().get_contents(), rng);
	}

	state.hash().update(io.send(*this));
}

/*
* Deserialize a Certificate Verify message
*/
Certificate_Verify::Certificate_Verify(in Vector!ubyte buf,
													Protocol_Version _version)
{
	TLS_Data_Reader reader("CertificateVerify", buf);

	if (_version.supports_negotiable_signature_algorithms())
	{
		m_hash_algo = Signature_Algorithms::hash_algo_name(reader.get_byte());
		m_sig_algo = Signature_Algorithms::sig_algo_name(reader.get_byte());
	}

	m_signature = reader.get_range!ubyte(2, 0, 65535);
}

/*
* Serialize a Certificate Verify message
*/
Vector!ubyte Certificate_Verify::serialize() const
{
	Vector!ubyte buf;

	if (m_hash_algo != "" && m_sig_algo != "")
	{
		buf.push_back(Signature_Algorithms::hash_algo_code(m_hash_algo));
		buf.push_back(Signature_Algorithms::sig_algo_code(m_sig_algo));
	}

	const ushort sig_len = m_signature.length;
	buf.push_back(get_byte(0, sig_len));
	buf.push_back(get_byte(1, sig_len));
	buf += m_signature;

	return buf;
}

/*
* Verify a Certificate Verify message
*/
bool Certificate_Verify::verify(const X509_Certificate cert,
										  const Handshake_State state) const
{
	Unique!Public_Key key = cert.subject_public_key();

	Pair!(string, Signature_Format) format =
		state.understand_sig_format(*key.get(), m_hash_algo, m_sig_algo, true);

	PK_Verifier verifier = new PK_Verifier(*key, format.first, format.second);
		scope(exit) delete verifier;
	if (state._version() == Protocol_Version::SSL_V3)
	{
		SafeVector!ubyte md5_sha = state.hash().final_ssl3(
			state.session_keys().master_secret());

		return verifier.verify_message(&md5_sha[16], md5_sha.length-16,
												 &m_signature[0], m_signature.length);
	}

	return verifier.verify_message(state.hash().get_contents(), m_signature);
}

}

}
