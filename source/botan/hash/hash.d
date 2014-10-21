/*
* Hash Function Base Class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.hash;
import botan.algo_base.buf_comp;
import string;
/**
* This class represents hash function (message digest) objects
*/
class HashFunction : Buffered_Computation
{
public:
	/**
	* @return new object representing the same algorithm as this
	*/
	abstract HashFunction clone() const;

	abstract void clear();

	abstract string name() const;

	/**
	* @return hash block size as defined for this algorithm
	*/
	abstract size_t hash_block_size() const { return 0; }
};