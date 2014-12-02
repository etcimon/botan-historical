/*
* Bcrypt Password Hashing
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.passhash.bcrypt;

import botan.constants;
static if (BOTAN_HAS_BCRYPT):

import botan.rng.rng;
import botan.utils.loadstor;
import botan.block.blowfish;
import botan.codec.base64;

/**
* Create a password hash using Bcrypt
* @param password = the password
* @param rng = a random number generator
* @param work_factor = how much work to do to slow down guessing attacks
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
* @param password = the password to check against
* @param hash = the stored hash to check against
*/
bool check_bcrypt(in string password, in string hash)
{
    if (hash.length != 60 ||
        hash[0] != '$' || hash[1] != '2' || hash[2] != 'a' ||
        hash[3] != '$' || hash[6] != '$')
    {
        return false;
    }
    
    const ushort workfactor = to!uint(hash[4 .. 7]);
    
    Vector!ubyte salt = bcrypt_base64_decode(hash[7 .. 30]);
    
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
    
    while (b64.length && b64[b64.length-1] == '=')
        b64 = b64[0 .. $];
    
    foreach (size_t i; 0 .. b64.length)
        b64[i] = OPENBSD_BASE64_SUB[cast(ubyte) b64[i]];
    
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
    
    foreach (size_t i; 0 .. input.length)
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
    
    Vector!ubyte ctext = Vector!ubyte(magic.ptr[0 .. magic.length]);
    
    Blowfish blowfish;
    
    // Include the trailing NULL ubyte
    blowfish.eks_key_schedule(cast(const ubyte*) pass.toStringz, pass.length + 1, salt.ptr,    work_factor);
    
    foreach (size_t i; 0 .. 64)
        blowfish.encrypt_n(ctext.ptr, ctext.ptr, 3);
    
    string salt_b64 = bcrypt_base64_encode(salt.ptr, salt.length);
    
    string work_factor_str = to!string(work_factor);
    if (work_factor_str.length == 1)
        work_factor_str = "0" ~ work_factor_str;
    
    return "$2a$" ~ work_factor_str ~ "$" ~ salt_b64[0 .. 22] ~ bcrypt_base64_encode(ctext.ptr, ctext.length - 1);
}


static if (BOTAN_TEST):
import botan.test;
import botan.rng.auto_rng;

unittest
{
    size_t fails = 0;
    
    // Generated by jBCrypt 0.3
    if (!check_bcrypt("abc", "$2a$05$DfPyLs.G6.To9fXEFgUL1O6HpYw3jIXgPcl/L3Qt3jESuWmhxtmpS"))
    {
        writeln("Bcrypt test 1 failed");
        fails++;
    }
    
    // http://www.openwall.com/lists/john-dev/2011/06/19/2
    if (!check_bcrypt("\xA3", "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"))
    {
        writeln("Bcrypt test 2 failed");
        fails++;
    }
    
    AutoSeeded_RNG rng;
    
    for(ushort level = 1; level != 5; ++level)
    {
        const string input = "some test passphrase 123";
        const string gen_hash = generate_bcrypt(input, rng, level);
        
        if (!check_bcrypt(input, gen_hash))
        {
            writeln("Gen and check for bcrypt failed: " ~ gen_hash ~ " not valid");
            ++fails;
        }
    }
    
    test_report("Bcrypt", 6, fails);
}
