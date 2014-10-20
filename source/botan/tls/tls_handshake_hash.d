/*
* TLS Handshake Hash
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_handshake_hash;
import botan.tls_exceptn;
import botan.libstate.libstate;
import botan.hash.hash;


/**
* Return a TLS Handshake Hash
*/
SafeVector!ubyte Handshake_Hash::flushInto(Protocol_Version _version,
														in string mac_algo) const
{
	AlgorithmFactory af = global_state().algorithm_factory();

	Unique!HashFunction hash;

	if (_version.supports_ciphersuite_specific_prf())
	{
		if (mac_algo == "MD5" || mac_algo == "SHA-1")
			hash.reset(af.make_hash_function("SHA-256"));
		else
			hash.reset(af.make_hash_function(mac_algo));
	}
	else
		hash.reset(af.make_hash_function("Parallel(MD5,SHA-160)"));

	hash.update(data);
	return hash.flush();
}

/**
* Return a SSLv3 Handshake Hash
*/
SafeVector!ubyte Handshake_Hash::final_ssl3(in SafeVector!ubyte secret) const
{
	const ubyte PAD_INNER = 0x36, PAD_OUTER = 0x5C;

	AlgorithmFactory af = global_state().algorithm_factory();

	Unique!HashFunction md5 = af.make_hash_function("MD5");
	Unique!HashFunction sha1 = af.make_hash_function("SHA-1");

	md5.update(data);
	sha1.update(data);

	md5.update(secret);
	sha1.update(secret);

	for (size_t i = 0; i != 48; ++i)
		md5.update(PAD_INNER);
	for (size_t i = 0; i != 40; ++i)
		sha1.update(PAD_INNER);

	SafeVector!ubyte inner_md5 = md5.flush(), inner_sha1 = sha1.flush();

	md5.update(secret);
	sha1.update(secret);

	for (size_t i = 0; i != 48; ++i)
		md5.update(PAD_OUTER);
	for (size_t i = 0; i != 40; ++i)
		sha1.update(PAD_OUTER);

	md5.update(inner_md5);
	sha1.update(inner_sha1);

	SafeVector!ubyte output;
	output += md5.flush();
	output += sha1.flush();
	return output;
}

}

}
