/*
* EMSA1 BSI
* (C) 1999-2008 Jack Lloyd
*	  2008 Falko Strenzke, FlexSecure GmbH
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa1_bsi.h>
/*
* EMSA1 BSI Encode Operation
*/
SafeVector!byte EMSA1_BSI::encoding_of(in SafeVector!byte msg,
														size_t output_bits,
														RandomNumberGenerator&)
{
	if(msg.size() != hash_output_length())
		throw new Encoding_Error("EMSA1_BSI::encoding_of: Invalid size for input");

	if(8*msg.size() <= output_bits)
		return msg;

	throw new Encoding_Error("EMSA1_BSI::encoding_of: max key input size exceeded");
}

}
