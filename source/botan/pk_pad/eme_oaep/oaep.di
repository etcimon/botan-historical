/*
* OAEP
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_OAEP_H__
#define BOTAN_OAEP_H__

#include <botan/eme.h>
#include <botan/kdf.h>
#include <botan/hash.h>

namespace Botan {

/**
* OAEP (called EME1 in IEEE 1363 and in earlier versions of the library)
*/
class OAEP : public EME
	{
	public:
		size_t maximum_input_size(size_t) const;

		/**
		* @param hash object to use for hashing (takes ownership)
		* @param P an optional label. Normally empty.
		*/
		OAEP(HashFunction* hash, in string P = "");
	private:
		SafeArray!byte pad(const byte[], size_t, size_t,
									  RandomNumberGenerator&) const;
		SafeArray!byte unpad(const byte[], size_t, size_t) const;

		SafeArray!byte m_Phash;
		std::unique_ptr<HashFunction> m_hash;
	};

}

#endif
