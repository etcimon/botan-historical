/*
* X9.42 PRF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_ANSI_X942_PRF_H__

#include <botan/kdf.h>
/**
* PRF from ANSI X9.42
*/
class X942_PRF : public KDF
{
	public:
		SafeArray!byte derive(size_t, const byte[], size_t,
										  const byte[], size_t) const;

		string name() const { return "X942_PRF(" + key_wrap_oid + ")"; }
		KDF* clone() const { return new X942_PRF(key_wrap_oid); }

		X942_PRF(in string oid);
	private:
		string key_wrap_oid;
};