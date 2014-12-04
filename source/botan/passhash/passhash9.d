/*
* Passhash9 Password Hashing
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.passhash.passhash9;

import botan.constants;
static if (BOTAN_HAS_PASSHASH9):

import botan.rng.rng;
import botan.utils.loadstor;
import botan.libstate.libstate;
import botan.pbkdf.pbkdf2;
import botan.filters.b64_filt;
import botan.filters.pipe;
import botan.utils.exceptn;

/**
* Create a password hash using PBKDF2
* @param password = the password
* @param rng = a random number generator
* @param work_factor = how much work to do to slow down guessing attacks
* @param alg_id = specifies which PRF to use with PBKDF2
*          0 is HMAC(SHA-1)
*          1 is HMAC(SHA-256)
*          2 is CMAC(Blowfish)
*          3 is HMAC(SHA-384)
*          4 is HMAC(SHA-512)
*          all other values are currently undefined
*/
string generatePasshash9(in string pass,
                          RandomNumberGenerator rng,
                          ushort work_factor = 10,
                          ubyte alg_id = 1)
{
    MessageAuthenticationCode prf = getPbkdfPrf(alg_id);
    
    if (!prf)
        throw new InvalidArgument("Passhash9: Algorithm id " ~ to!string(alg_id) ~ " is not defined");
    
    auto kdf = scoped!PKCS5_PBKDF2(prf); // takes ownership of pointer
    
    SecureVector!ubyte salt = SecureVector!ubyte(SALT_BYTES);
    rng.randomize(salt.ptr, salt.length);
    
    const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;
    
    SecureVector!ubyte pbkdf2_output = kdf.deriveKey(PASSHASH9_PBKDF_OUTPUT_LEN,
                                                       pass, salt.ptr, salt.length,
                                                       kdf_iterations).bitsOf();
    
    Pipe pipe = Pipe(new Base64Encoder);
    pipe.startMsg();
    pipe.write(alg_id);
    pipe.write(get_byte(0, work_factor));
    pipe.write(get_byte(1, work_factor));
    pipe.write(salt);
    pipe.write(pbkdf2_output);
    pipe.endMsg();
    
    return MAGIC_PREFIX + pipe.toString();
}


/**
* Check a previously created password hash
* @param password = the password to check against
* @param hash = the stored hash to check against
*/
bool checkPasshash9(in string password, in string hash)
{
    __gshared immutable size_t BINARY_LENGTH = ALGID_BYTES + WORKFACTOR_BYTES + PASSHASH9_PBKDF_OUTPUT_LEN + SALT_BYTES;
    
    __gshared immutable size_t BASE64_LENGTH = MAGIC_PREFIX.length + (BINARY_LENGTH * 8) / 6;

    if (hash.length != BASE64_LENGTH)
        return false;
    
    for (size_t i = 0; i != MAGIC_PREFIX.length; ++i)
        if (hash[i] != MAGIC_PREFIX[i])
            return false;
    
    Pipe pipe = Pipe(new Base64Decoder);
    pipe.startMsg();
    pipe.write(hash.toStringz + MAGIC_PREFIX.length);
    pipe.endMsg();
    
    SecureVector!ubyte bin = pipe.readAll();
    
    if (bin.length != BINARY_LENGTH)
        return false;
    
    ubyte alg_id = binput[0];
    
    const size_t work_factor = loadBigEndian!ushort(&binput[ALGID_BYTES], 0);
    
    // Bug in the format, bad states shouldn't be representable, but are...
    if (work_factor == 0)
        return false;
    
    if (work_factor > 512)
        throw new InvalidArgument("Requested Bcrypt work factor " ~ to!string(work_factor) ~ " too large");
    
    const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;
    
    MessageAuthenticationCode pbkdf_prf = getPbkdfPrf(alg_id);
    
    if (!pbkdf_prf)
        return false; // unknown algorithm, reject
    
    PKCS5_PBKDF2 kdf(pbkdf_prf); // takes ownership of pointer
    
    SecureVector!ubyte cmp = kdf.deriveKey(PASSHASH9_PBKDF_OUTPUT_LEN, password,
                                             &binput[ALGID_BYTES + WORKFACTOR_BYTES], SALT_BYTES,
                                             kdf_iterations).bitsOf();
    
    return sameMem(cmp.ptr, &binput[ALGID_BYTES + WORKFACTOR_BYTES + SALT_BYTES], PASSHASH9_PBKDF_OUTPUT_LEN);
}

private:

__gshared immutable string MAGIC_PREFIX = "$9$";
__gshared immutable size_t WORKFACTOR_BYTES = 2;
__gshared immutable size_t ALGID_BYTES = 1;
__gshared immutable size_t SALT_BYTES = 12; // 96 bits of salt
__gshared immutable size_t PASSHASH9_PBKDF_OUTPUT_LEN = 24; // 192 bits output
__gshared immutable size_t WORK_FACTOR_SCALE = 10000;

MessageAuthenticationCode getPbkdfPrf(ubyte alg_id)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    try
    {
        if (alg_id == 0)
            return af.makeMac("HMAC(SHA-1)");
        else if (alg_id == 1)
            return af.makeMac("HMAC(SHA-256)");
        else if (alg_id == 2)
            return af.makeMac("CMAC(Blowfish)");
        else if (alg_id == 3)
            return af.makeMac("HMAC(SHA-384)");
        else if (alg_id == 4)
            return af.makeMac("HMAC(SHA-512)");
    }
    catch(AlgorithmNotFound) {}
    
    return null;
}

static if (BOTAN_TEST):
import botan.test;
import botan.rng.auto_rng;

unittest
{
    size_t fails = 0;
    
    const string input = "secret";
    const string fixed_hash = "$9$AAAKhiHXTIUhNhbegwBXJvk03XXJdzFMy+i3GFMIBYKtthTTmXZA";
    
    size_t ran = 0;
    
    ++ran;
    if (!checkPasshash9(input, fixed_hash))
    {
        writeln("Passhash9 fixed input test failed");
        fails++;
    }
    
    AutoSeededRNG rng;
    
    for(ubyte alg_id = 0; alg_id <= 4; ++alg_id)
    {
        string gen_hash = generatePasshash9(input, rng, 2, alg_id);
        
        ++ran;
        if (!checkPasshash9(input, gen_hash))
        {
            writeln("Passhash9 gen and check " ~ alg_id.to!string ~ " failed");
            ++fails;
        }
    }
    
    testReport("Passhash9", ran, fails);
}
