/*
* SSLv3 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_SSLV3_PRF_H__

#include <botan/kdf.h>
/**
* PRF used in SSLv3
*/
class SSL3_PRF : public KDF
{
	public:
		SafeArray!byte derive(size_t, const byte[], size_t,
										  const byte[], size_t) const;

		string name() const { return "SSL3-PRF"; }
		KDF* clone() const { return new SSL3_PRF; }
};