/*
* OAEP
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.eme;
import botan.kdf;
import botan.hash;
/**
* OAEP (called EME1 in IEEE 1363 and in earlier versions of the library)
*/
class OAEP : EME
{
	public:
		size_t maximum_input_size(size_t) const;

		/**
		* @param hash object to use for hashing (takes ownership)
		* @param P an optional label. Normally empty.
		*/
		OAEP(HashFunction hash, in string P = "");
	private:
		SafeVector!ubyte pad(const ubyte[], size_t, size_t,
									  RandomNumberGenerator) const;
		SafeVector!ubyte unpad(const ubyte[], size_t, size_t) const;

		SafeVector!ubyte m_Phash;
		Unique!HashFunction m_hash;
};