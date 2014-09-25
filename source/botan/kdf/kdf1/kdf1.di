/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/kdf.h>
#include <botan/hash.h>
/**
* KDF1, from IEEE 1363
*/
class KDF1 : public KDF
{
	public:
		SafeVector!byte derive(size_t,
										  in byte[] secret, size_t secret_len,
										  in byte[] P, size_t P_len) const;

		string name() const { return "KDF1(" + hash->name() + ")"; }
		KDF* clone() const { return new KDF1(hash->clone()); }

		KDF1(HashFunction* h) : hash(h) {}
	private:
		std::unique_ptr<HashFunction> hash;
};