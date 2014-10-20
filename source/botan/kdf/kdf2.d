/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.kdf.kdf2;
import botan.kdf.kdf;
import botan.hash.hash;

/**
* KDF2, from IEEE 1363
*/
class KDF2 : KDF
{
public:
	/*
	* KDF2 Key Derivation Mechanism
	*/
	SafeVector!ubyte derive(size_t out_len,
	                              in ubyte* secret, size_t secret_len,
	                              in ubyte* P, size_t P_len) const
	{
		SafeVector!ubyte output;
		uint counter = 1;
		
		while(out_len && counter)
		{
			hash.update(secret, secret_len);
			hash.update_be(counter);
			hash.update(P, P_len);
			
			SafeVector!ubyte hash_result = hash.flush();
			
			size_t added = std.algorithm.min(hash_result.length, out_len);
			output += Pair(&hash_result[0], added);
			out_len -= added;
			
			++counter;
		}
		
		return output;
	}

	string name() const { return "KDF2(" ~ hash.name() ~ ")"; }
	KDF clone() const { return new KDF2(hash.clone()); }

	this(HashFunction h) { hash = h; }
private:
	Unique!HashFunction hash;
};