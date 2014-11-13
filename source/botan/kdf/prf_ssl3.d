/*
* SSLv3 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.kdf.kdf;
import botan.algo_base.symkey;
import botan.utils.exceptn;
import botan.hash.sha160;
import botan.hash.md5;
import botan.utils.types;

/**
* PRF used in SSLv3
*/
class SSL3_PRF : KDF
{
public:	
	/*
	* SSL3 PRF
	*/
	Secure_Vector!ubyte derive(size_t key_len,
	                        in ubyte* secret, size_t secret_len,
	                        in ubyte* seed, size_t seed_len) const
	{
		if (key_len > 416)
			throw new Invalid_Argument("SSL3_PRF: Requested key length is too large");
		
		auto md5 = scoped!MD5();
		auto sha1 = scoped!SHA_160();
		
		OctetString output;
		
		int counter = 0;
		while(key_len)
		{
			const size_t produce = std.algorithm.min(key_len, md5.output_length);
			
			output = output + next_hash(counter++, produce, md5, sha1,
			                            secret, secret_len, seed, seed_len);
			
			key_len -= produce;
		}
		
		return output.bits_of();
	}

	@property string name() const { return "SSL3-PRF"; }
	KDF clone() const { return new SSL3_PRF; }
}

	

private:

/*
* Return the next inner hash
*/
OctetString next_hash(size_t where, size_t want,
                      HashFunction md5, HashFunction sha1,
                      in ubyte* secret, size_t secret_len,
                      in ubyte* seed, size_t seed_len) pure
{
	assert(want <= md5.output_length,
	             "Output size producable by MD5");
	
	__gshared immutable ubyte ASCII_A_CHAR = 0x41;
	
	foreach (size_t j; 0 .. where + 1)
		sha1.update(cast(ubyte)(ASCII_A_CHAR + where));
	sha1.update(secret, secret_len);
	sha1.update(seed, seed_len);
	Secure_Vector!ubyte sha1_hash = sha1.flush();
	
	md5.update(secret, secret_len);
	md5.update(sha1_hash);
	Secure_Vector!ubyte md5_hash = md5.flush();
	
	return OctetString(&md5_hash[0], want);
}