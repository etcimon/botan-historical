/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.prf_x942;
import botan.der_enc;
import botan.oids;
import botan.sha160;
import botan.loadstor;
import algorithm;
namespace {

/*
* Encode an integer as an OCTET STRING
*/
Vector!( byte ) encode_x942_int(uint n)
{
	byte[4] n_buf = { 0 };
	store_be(n, n_buf);
	return DER_Encoder().encode(n_buf, 4, OCTET_STRING).get_contents_unlocked();
}

}

/*
* X9.42 PRF
*/
SafeVector!byte X942_PRF::derive(size_t key_len,
												in byte* secret, size_t secret_len,
												in byte* salt, size_t salt_len) const
{
	SHA_160 hash;
	const OID kek_algo(key_wrap_oid);

	SafeVector!byte key;
	uint counter = 1;

	while(key.size() != key_len && counter)
	{
		hash.update(secret, secret_len);

		hash.update(
			DER_Encoder().start_cons(SEQUENCE)

				.start_cons(SEQUENCE)
					.encode(kek_algo)
					.raw_bytes(encode_x942_int(counter))
				.end_cons()

				.encode_if (salt_len != 0,
					DER_Encoder()
						.start_explicit(0)
							.encode(salt, salt_len, OCTET_STRING)
						.end_explicit()
					)

				.start_explicit(2)
					.raw_bytes(encode_x942_int(cast(uint)(8 * key_len)))
				.end_explicit()

			.end_cons().get_contents()
			);

		SafeVector!byte digest = hash.flush();
		const size_t needed = std.algorithm.min(digest.size(), key_len - key.size());
		key += Pair(&digest[0], needed);

		++counter;
	}

	return key;
}

/*
* X9.42 Constructor
*/
X942_PRF::X942_PRF(in string oid)
{
	if (OIDS::have_oid(oid))
		key_wrap_oid = OIDS::lookup(oid).as_string();
	else
		key_wrap_oid = oid;
}

}
