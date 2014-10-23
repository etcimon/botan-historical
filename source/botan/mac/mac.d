/*
* Base class for message authentiction codes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.mac;
import botan.algo_base.buf_comp;
import botan.algo_base.sym_algo;
import string;

import botan.utils.mem_ops;

/**
* This class represents Message Authentication Code (MAC) objects.
*/
class MessageAuthenticationCode : Buffered_Computation, SymmetricAlgorithm
{
public:
	/**
	* Verify a MAC.
	* @param input the MAC to verify as a ubyte array
	* @param length the length of param in
	* @return true if the MAC is valid, false otherwise
	*/
	final bool verify_mac(in ubyte* mac, size_t length)
	{
		Secure_Vector!ubyte our_mac = flush();
		
		if (our_mac.length != length)
			return false;
		
		return same_mem(&our_mac[0], &mac[0], length);
	}

	/**
	* Get a new object representing the same algorithm as this
	*/
	abstract MessageAuthenticationCode clone() const;

	/**
	* Get the name of this algorithm.
	* @return name of this algorithm
	*/
	abstract @property string name() const;
};
