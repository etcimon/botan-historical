/*
* EME PKCS#1 v1.5
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/eme.h>
/**
* EME from PKCS #1 v1.5
*/
class EME_PKCS1v15 : public EME
{
	public:
		size_t maximum_input_size(size_t) const;
	private:
		SafeArray!byte pad(const byte[], size_t, size_t,
									  RandomNumberGenerator&) const;
		SafeArray!byte unpad(const byte[], size_t, size_t) const;
};