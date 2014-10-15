/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.kdf;
import botan.hash.hash;
/**
* KDF1, from IEEE 1363
*/
class KDF1 : KDF
{
	public:
		SafeVector!ubyte derive(size_t,
										  in ubyte* secret, size_t secret_len,
										  in ubyte* P, size_t P_len) const;

		string name() const { return "KDF1(" ~ hash.name() ~ ")"; }
		KDF* clone() const { return new KDF1(hash.clone()); }

		KDF1(HashFunction h) : hash(h) {}
	private:
		Unique!HashFunction hash;
};