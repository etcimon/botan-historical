/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.kdf.prf_x942;

import botan.kdf.kdf;
import botan.asn1.der_enc;
import botan.asn1.oids;
import botan.hash.sha160;
import botan.utils.loadstor;
import std.algorithm;

/**
* PRF from ANSI X9.42
*/
class X942_PRF : KDF
{
public:
	/*
	* X9.42 PRF
	*/
	Secure_Vector!ubyte derive(size_t key_len,
	                        in ubyte* secret, size_t secret_len,
	                        in ubyte* salt, size_t salt_len) const
	{
		SHA_160 hash;
		const OID kek_algo = OID(m_key_wrap_oid);
		
		Secure_Vector!ubyte key;
		uint counter = 1;
		
		while (key.length != key_len && counter)
		{
			hash.update(secret, secret_len);
			
			hash.update(
				DER_Encoder().start_cons(ASN1_Tag.SEQUENCE)
				
				.start_cons(ASN1_Tag.SEQUENCE)
				.encode(kek_algo)
				.raw_bytes(encode_x942_int(counter))
				.end_cons()
				
				.encode_if (salt_len != 0,
			            DER_Encoder()
			            .start_explicit(0)
			            .encode(salt, salt_len, ASN1_Tag.OCTET_STRING)
			            .end_explicit()
			            )
				
				.start_explicit(2)
				.raw_bytes(encode_x942_int(cast(uint)(8 * key_len)))
				.end_explicit()
				
				.end_cons().get_contents()
				);
			
			Secure_Vector!ubyte digest = hash.flush();
			const size_t needed = std.algorithm.min(digest.length, key_len - key.length);
			key += Pair(digest.ptr, needed);
			
			++counter;
		}
		
		return key;
	}


	@property string name() const { return "X942_PRF(" ~ m_key_wrap_oid ~ ")"; }
	KDF clone() const { return new X942_PRF(m_key_wrap_oid); }
	/*
	* X9.42 Constructor
	*/
	this(in string oid)
	{
		if (OIDS.have_oid(oid))
			m_key_wrap_oid = OIDS.lookup(oid).toString();
		else
			m_key_wrap_oid = oid;
	}
private:
	string m_key_wrap_oid;
}

private:

/*
* Encode an integer as an OCTET STRING
*/
Vector!ubyte encode_x942_int(uint n)
{
	ubyte[4] n_buf;
	store_be(n, n_buf);
	return DER_Encoder().encode(n_buf.ptr, 4, ASN1_Tag.OCTET_STRING).get_contents_unlocked();
}