/*
* Hash Function Identification
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.hash_id;

import botan.alloc.secmem;
import string;
import botan.utils.exceptn;

/**
* Return the PKCS #1 hash identifier
* @see RFC 3447 section 9.2
* @param hash_name the name of the hash function
* @return ubyte sequence identifying the hash
* @throw new Invalid_Argument if the hash has no known PKCS #1 hash id
*/
Vector!ubyte pkcs_hash_id(in string name)
{
	// Special case for SSL/TLS RSA signatures
	if (name == "Parallel(MD5,SHA-160)")
		return Vector!ubyte();
	
	if (name == "MD2")
		return Vector!ubyte(MD2_PKCS_ID,
		                    MD2_PKCS_ID + (MD2_PKCS_ID).sizeof);
	
	if (name == "MD5")
		return Vector!ubyte(MD5_PKCS_ID,
		                    MD5_PKCS_ID + (MD5_PKCS_ID).sizeof);
	
	if (name == "RIPEMD-128")
		return Vector!ubyte(RIPEMD_128_PKCS_ID,
		                    RIPEMD_128_PKCS_ID + (RIPEMD_128_PKCS_ID).sizeof);
	
	if (name == "RIPEMD-160")
		return Vector!ubyte(RIPEMD_160_PKCS_ID,
		                    RIPEMD_160_PKCS_ID + (RIPEMD_160_PKCS_ID).sizeof);
	
	if (name == "SHA-160")
		return Vector!ubyte(SHA_160_PKCS_ID,
		                    SHA_160_PKCS_ID + (SHA_160_PKCS_ID).sizeof);
	
	if (name == "SHA-224")
		return Vector!ubyte(SHA_224_PKCS_ID,
		                    SHA_224_PKCS_ID + (SHA_224_PKCS_ID).sizeof);
	
	if (name == "SHA-256")
		return Vector!ubyte(SHA_256_PKCS_ID,
		                    SHA_256_PKCS_ID + (SHA_256_PKCS_ID).sizeof);
	
	if (name == "SHA-384")
		return Vector!ubyte(SHA_384_PKCS_ID,
		                    SHA_384_PKCS_ID + (SHA_384_PKCS_ID).sizeof);
	
	if (name == "SHA-512")
		return Vector!ubyte(SHA_512_PKCS_ID,
		                    SHA_512_PKCS_ID + (SHA_512_PKCS_ID).sizeof);
	
	if (name == "Tiger(24,3)")
		return Vector!ubyte(TIGER_PKCS_ID,
		                    TIGER_PKCS_ID + (TIGER_PKCS_ID).sizeof);
	
	throw new Invalid_Argument("No PKCS #1 identifier for " ~ name);
}

/**
* Return the IEEE 1363 hash identifier
* @param hash_name the name of the hash function
* @return ubyte code identifying the hash, or 0 if not known
*/

ubyte ieee1363_hash_id(in string name)
{
	if (name == "SHA-160")	 return 0x33;
	
	if (name == "SHA-224")	 return 0x38;
	if (name == "SHA-256")	 return 0x34;
	if (name == "SHA-384")	 return 0x36;
	if (name == "SHA-512")	 return 0x35;
	
	if (name == "RIPEMD-160") return 0x31;
	if (name == "RIPEMD-128") return 0x32;
	
	if (name == "Whirlpool")  return 0x37;
	
	return 0;
}


private:

immutable ubyte[] MD2_PKCS_ID = [
	0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
	0xF7, 0x0D, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10 ];

immutable ubyte[] MD5_PKCS_ID = [
	0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86,
	0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10 ];

immutable ubyte[] RIPEMD_128_PKCS_ID = [
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02,
	0x02, 0x05, 0x00, 0x04, 0x14 ];

immutable ubyte[] RIPEMD_160_PKCS_ID = [
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x24, 0x03, 0x02,
	0x01, 0x05, 0x00, 0x04, 0x14 ];

immutable ubyte[] SHA_160_PKCS_ID = [
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02,
	0x1A, 0x05, 0x00, 0x04, 0x14 ];

immutable ubyte[] SHA_224_PKCS_ID = [
	0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C ];

immutable ubyte[] SHA_256_PKCS_ID = [
	0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 ];

immutable ubyte[] SHA_384_PKCS_ID = [
	0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 ];

immutable ubyte[] SHA_512_PKCS_ID = [
	0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 ];

immutable ubyte[] TIGER_PKCS_ID = [
	0x30, 0x29, 0x30, 0x0D, 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04,
	0x01, 0xDA, 0x47, 0x0C, 0x02, 0x05, 0x00, 0x04, 0x18 ];