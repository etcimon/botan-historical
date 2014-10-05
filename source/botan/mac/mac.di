/*
* Base class for message authentiction codes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.algo_base.buf_comp;
import botan.algo_base.sym_algo;
import string;
/**
* This class represents Message Authentication Code (MAC) objects.
*/
class MessageAuthenticationCode : public Buffered_Computation,
								  public SymmetricAlgorithm
{
	public:
		/**
		* Verify a MAC.
		* @param in the MAC to verify as a ubyte array
		* @param length the length of param in
		* @return true if the MAC is valid, false otherwise
		*/
		abstract bool verify_mac(in ubyte* input, size_t length);

		/**
		* Get a new object representing the same algorithm as *this
		*/
		abstract MessageAuthenticationCode clone() const;

		/**
		* Get the name of this algorithm.
		* @return name of this algorithm
		*/
		abstract string name() const;
};