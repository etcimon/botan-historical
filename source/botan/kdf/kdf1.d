/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.kdf.kdf1;

import botan.kdf.kdf;
import botan.hash.hash;

/**
* KDF1, from IEEE 1363
*/
class KDF1 : KDF
{
public:
	/*
	* KDF1 Key Derivation Mechanism
	*/
	Secure_Vector!ubyte derive(size_t,
	                        in ubyte* secret, size_t secret_len,
	                        in ubyte* P, size_t P_len) const
	{
		hash.update(secret, secret_len);
		hash.update(P, P_len);
		return hash.flush();
	}


	@property string name() const { return "KDF1(" ~ hash.name ~ ")"; }
	KDF clone() const { return new KDF1(hash.clone()); }

	this(HashFunction h) 
	{
		hash = h;
	}
private:
	Unique!HashFunction hash;
};

