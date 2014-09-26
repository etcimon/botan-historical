/*
* Hash Function Base Class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/buf_comp.h>
#include <string>
/**
* This class represents hash function (message digest) objects
*/
class HashFunction : public Buffered_Computation
{
	public:
		/**
		* @return new object representing the same algorithm as *this
		*/
		abstract HashFunction* clone() const;

		abstract void clear();

		abstract string name() const;

		/**
		* @return hash block size as defined for this algorithm
		*/
		abstract size_t hash_block_size() const { return 0; }
};