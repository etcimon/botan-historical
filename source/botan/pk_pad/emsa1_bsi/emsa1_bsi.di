/*
* EMSA1 BSI Variant
* (C) 1999-2008 Jack Lloyd
*	  2007 FlexSecure GmbH
*
* Distributed under the terms of the botan license.
*/

import botan.emsa1;
/**
* EMSA1_BSI is a variant of EMSA1 specified by the BSI. It accepts
* only hash values which are less or equal than the maximum key
* length. The implementation comes from InSiTo
*/
class EMSA1_BSI : public EMSA1
{
	public:
		/**
		* @param hash the hash object to use
		*/
		EMSA1_BSI(HashFunction* hash) : EMSA1(hash) {}
	private:
		SafeVector!byte encoding_of(in SafeVector!byte, size_t,
												 RandomNumberGenerator& rng);
};