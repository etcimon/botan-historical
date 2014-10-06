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
class EME_PKCS1v15 : EME
{
	public:
		size_t maximum_input_size(size_t) const;
	private:
		SafeVector!ubyte pad(const ubyte[], size_t, size_t,
									  RandomNumberGenerator) const;
		SafeVector!ubyte unpad(const ubyte[], size_t, size_t) const;
};