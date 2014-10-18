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
class EMSA1_BSI : EMSA1
{
public:
	/**
	* @param hash the hash object to use
	*/
	this(HashFunction hash)
	{
		super(hash);
	}
private:
	/*
	* EMSA1 BSI Encode Operation
	*/
	SafeVector!ubyte encoding_of(in SafeVector!ubyte msg,
	                             size_t output_bits,
	                             RandomNumberGenerator)
	{
		if (msg.size() != hash_output_length())
			throw new Encoding_Error("EMSA1_BSI::encoding_of: Invalid size for input");
		
		if (8*msg.size() <= output_bits)
			return msg;
		
		throw new Encoding_Error("EMSA1_BSI::encoding_of: max key input size exceeded");
	}
};

