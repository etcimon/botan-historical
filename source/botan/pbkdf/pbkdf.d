/*
* PBKDF
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbkdf.pbkdf;

import botan.algo_base.symkey;
import std.datetime;
import std.exception;
import botan.utils.types;

/**
* Base class for PBKDF (password based key derivation function)
* implementations. Converts a password into a key using a salt
* and iterated hashing to make brute force attacks harder.
*/
interface PBKDF
{
public:
    /**
    * @return new instance of this same algorithm
    */
    abstract PBKDF clone() const;

    abstract @property string name() const;

    /**
    * Derive a key from a passphrase
    * @param output_len = the desired length of the key to produce
    * @param passphrase = the password to derive the key from
    * @param salt = a randomly chosen salt
    * @param salt_len = length of salt in bytes
    * @param iterations = the number of iterations to use (use 10K or more)
    */
    final OctetString deriveKey(size_t output_len,
                                in string passphrase,
                                const(ubyte)* salt, size_t salt_len,
                                size_t iterations) const
    {
        if (iterations == 0)
            throw new InvalidArgument(name ~ ": Invalid iteration count");
        
        auto derived = keyDerivation(output_len, passphrase,
                                     salt, salt_len, iterations,
                                     Duration.zero);
        
        assert(derived.first == iterations,
                     "PBKDF used the correct number of iterations");
        
        return derived.second;
    }

    /**
    * Derive a key from a passphrase
    * @param output_len = the desired length of the key to produce
    * @param passphrase = the password to derive the key from
    * @param salt = a randomly chosen salt
    * @param iterations = the number of iterations to use (use 10K or more)
    */
    final OctetString deriveKey(Alloc)(size_t output_len,
                                       in string passphrase,
                                       in FreeListRef!(VectorImpl!( ubyte, Alloc )) salt,
                                       size_t iterations) const
    {
        return deriveKey(output_len, passphrase, salt.ptr, salt.length, iterations);
    }

    /**
    * Derive a key from a passphrase
    * @param output_len = the desired length of the key to produce
    * @param passphrase = the password to derive the key from
    * @param salt = a randomly chosen salt
    * @param salt_len = length of salt in bytes
    * @param loop_for = is how long to run the PBKDF
    * @param iterations = is set to the number of iterations used
    */
    final OctetString deriveKey(size_t output_len,
                           in string passphrase,
                           const(ubyte)* salt, size_t salt_len,
                           Duration loop_for,
                           ref size_t iterations) const
    {
        auto derived = keyDerivation(output_len, passphrase, salt, salt_len, 0, loop_for);
        
        iterations = derived.first;
        
        return derived.second;
    }

    /**
    * Derive a key from a passphrase using a certain amount of time
    * @param output_len = the desired length of the key to produce
    * @param passphrase = the password to derive the key from
    * @param salt = a randomly chosen salt
    * @param loop_for = is how long to run the PBKDF
    * @param iterations = is set to the number of iterations used
    */
    final OctetString deriveKey(Alloc)(size_t output_len,
                                       in string passphrase,
                                       in Vector!( ubyte, Alloc ) salt,
                                       Duration loop_for,
                                       ref size_t iterations) const
    {
        return deriveKey(output_len, passphrase, salt.ptr, salt.length, loop_for, iterations);
    }

    /**
    * Derive a key from a passphrase for a number of iterations
    * specified by either iterations or if iterations == 0 then
    * running until seconds time has elapsed.
    *
    * @param output_len = the desired length of the key to produce
    * @param passphrase = the password to derive the key from
    * @param salt = a randomly chosen salt
    * @param salt_len = length of salt in bytes
    * @param iterations = the number of iterations to use (use 10K or more)
    * @param loop_for = if iterations is zero, then instead the PBKDF is
    *          run until duration has passed.
    * @return the number of iterations performed and the derived key
    */
    abstract Pair!(size_t, OctetString)
        keyDerivation(size_t output_len,
                      in string passphrase,
                      const(ubyte)* salt, size_t salt_len,
                      size_t iterations,
                      Duration loop_for) const;
}

unittest {
    import botan.tests;
    import botan.codec.hex;

    auto test = (string input) {
        return runTests(input, "PBKDF", "Output", true,
                         (string[string] vec) {
                            Unique!PBKDF pbkdf = getPbkdf(vec["PBKDF"]);
                            
                            const size_t iterations = to!size_t(vec["Iterations"]);
                            const size_t outlen = to!size_t(vec["OutputLen"]);
                            const auto salt = hexDecode(vec["Salt"]);
                            const string pass = vec["Passphrase"];
                            
                            const auto key = pbkdf.deriveKey(outlen, pass, &salt[0], salt.length, iterations).bitsOf();
                            return hexEncode(key);
                        });
    };
    
    size_t fails = runTestsInDir("test_data/pbkdf", test);

    testReport("pbkdf", 1, fails);
}