/*
* SSLv3 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.kdf;
/**
* PRF used in SSLv3
*/
class SSL3_PRF : KDF
{
	public:
		SafeVector!ubyte derive(size_t, const ubyte[], size_t,
										  const ubyte[], size_t) const;

		string name() const { return "SSL3-PRF"; }
		KDF* clone() const { return new SSL3_PRF; }
};