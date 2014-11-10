/*
* Bcrypt Password Hashing
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.passhash.bcrypt;

import botan.rng.rng;
import botan.utils.loadstor;
import botan.block.blowfish;
import botan.codec.base64;
/**
* Create a password hash using Bcrypt
* @param password the password
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
*
* @see http://www.usenix.org/events/usenix99/provos/provos_html/
*/
string generate_bcrypt(in string password,
                       RandomNumberGenerator rng,
                       ushort work_factor = 10)
{
	return make_bcrypt(password, unlock(rng.random_vec(16)), work_factor);
}

/**
* Check a previously created password hash
* @param password the password to check against
* @param hash the stored hash to check against
*/
bool check_bcrypt(in string password, in string hash)
{
	if (hash.length != 60 ||
	    hash[0] != '$' || hash[1] != '2' || hash[2] != 'a' ||
	hash[3] != '$' || hash[6] != '$')
	{
		return false;
	}
	
	const ushort workfactor = to_uint(hash.substr(4, 2));
	
	Vector!ubyte salt = bcrypt_base64_decode(hash.substr(7, 22));
	
	const string compare = make_bcrypt(password, salt, workfactor);
	
	return (hash == compare);
}


private:

string bcrypt_base64_encode(in ubyte* input, size_t length)
{
	// Bcrypt uses a non-standard base64 alphabet
	__gshared immutable ubyte[256] OPENBSD_BASE64_SUB = [
		0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x38, 0x80, 0x80, 0x80, 0x39,
		0x79, 0x7A, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x2E, 0x2F, 0x41, 0x42, 0x43, 0x44, 0x45,
		0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51,
		0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x59, 0x5A, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
		0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
		0x76, 0x77, 0x78, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80
	];
	
	string b64 = base64_encode(input, length);
	
	while(b64.length && b64[b64.length-1] == '=')
		b64 = b64.substr(0, b64.length - 1);
	
	for (size_t i = 0; i != b64.length; ++i)
		b64[i] = OPENBSD_BASE64_SUB[cast(ubyte)(b64[i])];
	
	return b64;
}

Vector!ubyte bcrypt_base64_decode(string input)
{
	__gshared immutable ubyte[256] OPENBSD_BASE64_SUB = [
		0x00, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x41, 0x42,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2B, 0x2F, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
		0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
		0x56, 0x57, 0x58, 0x59, 0x5A, 0x61, 0x62, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D,
		0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
		0x7A, 0x30, 0x31, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		0x80, 0x80, 0x80, 0x80
	];
	
	for (size_t i = 0; i != input.length; ++i)
		input[i] = OPENBSD_BASE64_SUB[cast(ubyte)(input[i])];
	
	return unlock(base64_decode(input));
}

string make_bcrypt(in string pass,
                   in Vector!ubyte salt,
                   ushort work_factor)
{
	__gshared immutable ubyte[24] magic = [
		0x4F, 0x72, 0x70, 0x68, 0x65, 0x61, 0x6E, 0x42,
		0x65, 0x68, 0x6F, 0x6C, 0x64, 0x65, 0x72, 0x53,
		0x63, 0x72, 0x79, 0x44, 0x6F, 0x75, 0x62, 0x74
	];
	
	Vector!ubyte ctext = Vector!ubyte(magic, magic + (magic).sizeof);
	
	Blowfish blowfish;
	
	// Include the trailing NULL ubyte
	blowfish.eks_key_schedule(cast(const ubyte*)(pass.toStringz),
	                          pass.length + 1,
	                          &salt[0],
	work_factor);
	
	for (size_t i = 0; i != 64; ++i)
		blowfish.encrypt_n(&ctext[0], &ctext[0], 3);
	
	string salt_b64 = bcrypt_base64_encode(&salt[0], salt.length);
	
	string work_factor_str = std.conv.to!string(work_factor);
	if (work_factor_str.length == 1)
		work_factor_str = "0" ~ work_factor_str;
	
	return "$2a$" ~ work_factor_str +
		"$" ~ salt_b64.substr(0, 22) +
			bcrypt_base64_encode(&ctext[0], ctext.length - 1);
}

