/*
* Passhash9 Password Hashing
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.passhash.passhash9;

import botan.rng.rng;
import botan.utils.loadstor;
import botan.libstate.libstate;
import botan.pbkdf.pbkdf2;
import botan.filters.b64_filt;
import botan.filters.pipe;
import botan.utils.exceptn;

/**
* Create a password hash using PBKDF2
* @param password the password
* @param rng a random number generator
* @param work_factor how much work to do to slow down guessing attacks
* @param alg_id specifies which PRF to use with PBKDF2
*		  0 is HMAC(SHA-1)
*		  1 is HMAC(SHA-256)
*		  2 is CMAC(Blowfish)
*		  3 is HMAC(SHA-384)
*		  4 is HMAC(SHA-512)
*		  all other values are currently undefined
*/
string generate_passhash9(in string pass,
                          RandomNumberGenerator rng,
                          ushort work_factor = 10,
                          ubyte alg_id = 1)
{
	MessageAuthenticationCode prf = get_pbkdf_prf(alg_id);
	
	if (!prf)
		throw new Invalid_Argument("Passhash9: Algorithm id " ~ to!string(alg_id) ~ " is not defined");
	
	auto kdf = scoped!PKCS5_PBKDF2(prf); // takes ownership of pointer
	
	Secure_Vector!ubyte salt = Secure_Vector!ubyte(SALT_BYTES);
	rng.randomize(salt.ptr, salt.length);
	
	const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;
	
	Secure_Vector!ubyte pbkdf2_output = kdf.derive_key(PASSHASH9_PBKDF_OUTPUT_LEN,
	                                                   pass, salt.ptr, salt.length,
	                                                   kdf_iterations).bits_of();
	
	Pipe pipe = Pipe(new Base64_Encoder);
	pipe.start_msg();
	pipe.write(alg_id);
	pipe.write(get_byte(0, work_factor));
	pipe.write(get_byte(1, work_factor));
	pipe.write(salt);
	pipe.write(pbkdf2_output);
	pipe.end_msg();
	
	return MAGIC_PREFIX + pipe.toString();
}


/**
* Check a previously created password hash
* @param password the password to check against
* @param hash the stored hash to check against
*/
bool check_passhash9(in string password, in string hash)
{
	__gshared immutable size_t BINARY_LENGTH = ALGID_BYTES + WORKFACTOR_BYTES + PASSHASH9_PBKDF_OUTPUT_LEN + SALT_BYTES;
	
	__gshared immutable size_t BASE64_LENGTH = MAGIC_PREFIX.length + (BINARY_LENGTH * 8) / 6;

	if (hash.length != BASE64_LENGTH)
		return false;
	
	for (size_t i = 0; i != MAGIC_PREFIX.length; ++i)
		if (hash[i] != MAGIC_PREFIX[i])
			return false;
	
	Pipe pipe = Pipe(new Base64_Decoder);
	pipe.start_msg();
	pipe.write(hash.toStringz + MAGIC_PREFIX.length);
	pipe.end_msg();
	
	Secure_Vector!ubyte bin = pipe.read_all();
	
	if (bin.length != BINARY_LENGTH)
		return false;
	
	ubyte alg_id = binput[0];
	
	const size_t work_factor = load_be!ushort(&binput[ALGID_BYTES], 0);
	
	// Bug in the format, bad states shouldn't be representable, but are...
	if (work_factor == 0)
		return false;
	
	if (work_factor > 512)
		throw new Invalid_Argument("Requested Bcrypt work factor " ~ to!string(work_factor) ~ " too large");
	
	const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;
	
	MessageAuthenticationCode pbkdf_prf = get_pbkdf_prf(alg_id);
	
	if (!pbkdf_prf)
		return false; // unknown algorithm, reject
	
	PKCS5_PBKDF2 kdf(pbkdf_prf); // takes ownership of pointer
	
	Secure_Vector!ubyte cmp = kdf.derive_key(PASSHASH9_PBKDF_OUTPUT_LEN, password,
	                                         &binput[ALGID_BYTES + WORKFACTOR_BYTES], SALT_BYTES,
	                                         kdf_iterations).bits_of();
	
	return same_mem(cmp.ptr, &binput[ALGID_BYTES + WORKFACTOR_BYTES + SALT_BYTES], PASSHASH9_PBKDF_OUTPUT_LEN);
}

private:

__gshared immutable string MAGIC_PREFIX = "$9$";
__gshared immutable size_t WORKFACTOR_BYTES = 2;
__gshared immutable size_t ALGID_BYTES = 1;
__gshared immutable size_t SALT_BYTES = 12; // 96 bits of salt
__gshared immutable size_t PASSHASH9_PBKDF_OUTPUT_LEN = 24; // 192 bits output
__gshared immutable size_t WORK_FACTOR_SCALE = 10000;

MessageAuthenticationCode get_pbkdf_prf(ubyte alg_id)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	
	try
	{
		if (alg_id == 0)
			return af.make_mac("HMAC(SHA-1)");
		else if (alg_id == 1)
			return af.make_mac("HMAC(SHA-256)");
		else if (alg_id == 2)
			return af.make_mac("CMAC(Blowfish)");
		else if (alg_id == 3)
			return af.make_mac("HMAC(SHA-384)");
		else if (alg_id == 4)
			return af.make_mac("HMAC(SHA-512)");
	}
	catch(Algorithm_Not_Found) {}
	
	return null;
}