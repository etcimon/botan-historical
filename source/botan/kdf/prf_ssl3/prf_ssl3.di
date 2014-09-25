/*
* SSLv3 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/kdf.h>
/**
* PRF used in SSLv3
*/
class SSL3_PRF : public KDF
{
	public:
		SafeVector!byte derive(size_t, const byte[], size_t,
										  const byte[], size_t) const;

		string name() const { return "SSL3-PRF"; }
		KDF* clone() const { return new SSL3_PRF; }
};