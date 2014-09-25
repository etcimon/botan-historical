/*
* Hash Function Base Class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_HASH_FUNCTION_BASE_CLASS_H__
#define BOTAN_HASH_FUNCTION_BASE_CLASS_H__

#include <botan/buf_comp.h>
#include <string>

namespace Botan {

/**
* This class represents hash function (message digest) objects
*/
class HashFunction : public Buffered_Computation
	{
	public:
		/**
		* @return new object representing the same algorithm as *this
		*/
		abstract HashFunction* clone() const = 0;

		abstract void clear() = 0;

		abstract string name() const = 0;

		/**
		* @return hash block size as defined for this algorithm
		*/
		abstract size_t hash_block_size() const { return 0; }
	};

}

#endif
