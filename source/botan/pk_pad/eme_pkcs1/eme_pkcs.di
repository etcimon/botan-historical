/*
* EME PKCS#1 v1.5
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.eme;
/**
* EME from PKCS #1 v1.5
*/
class EME_PKCS1v15 : public EME
{
	public:
		size_t maximum_input_size(size_t) const;
	private:
		SafeVector!byte pad(const byte[], size_t, size_t,
									  RandomNumberGenerator&) const;
		SafeVector!byte unpad(const byte[], size_t, size_t) const;
};