/*
* KDF2
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.kdf;
import botan.hash;
/**
* KDF2, from IEEE 1363
*/
class KDF2 : public KDF
{
	public:
		SafeVector!byte derive(size_t, const byte[], size_t,
										  const byte[], size_t) const;

		string name() const { return "KDF2(" + hash->name() + ")"; }
		KDF* clone() const { return new KDF2(hash->clone()); }

		KDF2(HashFunction* h) : hash(h) {}
	private:
		std::unique_ptr<HashFunction> hash;
};