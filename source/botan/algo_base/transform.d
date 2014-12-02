/*
* Transformations of data
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.algo_base.transform;

import botan.utils.memory.zeroize;
import botan.algo_base.key_spec;
import botan.utils.exceptn;
import botan.algo_base.symkey;
// import string;
import botan.utils.types;

/**
* Interface for general transformations on data
*/
class Transformation
{
public:
    /**
    * Begin processing a message.
    * @param nonce = the per message nonce
    */    
    final Secure_Vector!ubyte start_vec(Alloc)(in Vector!( ubyte, Alloc ) nonce)
    {
        return start(nonce.ptr, nonce.length);
    }

    /**
    * Begin processing a message.
    * @param nonce = the per message nonce
    * @param nonce_len = length of nonce
    */
    abstract Secure_Vector!ubyte start(in ubyte* nonce, size_t nonce_len);

    /**
    * Process some data. Input must be in size update_granularity() ubyte blocks.
    * @param blocks = in/out paramter which will possibly be resized
    * @param offset = an offset into blocks to begin processing
    */
    abstract void update(Secure_Vector!ubyte blocks, size_t offset = 0);

    /**
    * Complete processing of a message.
    *
    * @param final_block = in/out parameter which must be at least
    *          minimum_final_size() bytes, and will be set to any final output
    * @param offset = an offset into final_block to begin processing
    */
    abstract void finish(Secure_Vector!ubyte final_block, size_t offset = 0);

    /**
    * Returns the size of the output if this transform is used to process a
    * message with input_length bytes. Will throw new if unable to give a precise
    * answer.
    */
    abstract size_t output_length(size_t input_length) const;

    /**
    * @return size of required blocks to update
    */
    abstract size_t update_granularity() const;

    /**
    * @return required minimium size to finalize() - may be any
    *            length larger than this.
    */
    abstract size_t minimum_final_size() const;

    /**
    * Return the default size for a nonce
    */
    abstract size_t default_nonce_length() const;

    /**
    * Return true iff nonce_len is a valid length for the nonce
    */
    abstract bool valid_nonce_length(size_t nonce_len) const;

    /**
    * Return some short name describing the provider of this tranformation.
    * Useful in cases where multiple implementations are available (eg,
    * different implementations of AES). Default "core" is used for the
    * 'standard' implementation included in the library.
    */
    abstract string provider() const { return "core"; }

    abstract @property string name() const;

    abstract void clear();

    ~this() {}
}

class Keyed_Transform : Transformation
{
public:
    /**
    * @return object describing limits on key size
    */
    abstract Key_Length_Specification key_spec() const;

    /**
    * Check whether a given key length is valid for this algorithm.
    * @param length = the key length to be checked.
    * @return true if the key length is valid.
    */
    final bool valid_keylength(size_t length) const
    {
        return key_spec().valid_keylength(length);
    }

    final void set_key(Alloc)(in Vector!( ubyte, Alloc ) key)
    {
        set_key(key.ptr, key.length);
    }

    final void set_key(in SymmetricKey key)
    {
        set_key(key.ptr, key.length);
    }

    /**
    * Set the symmetric key of this transform
    * @param key = contains the key material
    * @param length = in bytes of key param
    */
    final void set_key(in ubyte* key, size_t length)
    {
        if (!valid_keylength(length))
            throw new Invalid_Key_Length(name, length);
        key_schedule(key, length);
    }

private:
    abstract void key_schedule(in ubyte* key, size_t length);
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import core.atomic;

__gshared size_t total_tests;

Transformation get_transform(string algo)
{
    throw new Exception("Unknown transform " ~ algo);
}

Secure_Vector!ubyte transform_test(string algo,
                                   in Secure_Vector!ubyte nonce,
                                   in Secure_Vector!ubyte /*key*/,
                                   in Secure_Vector!ubyte input)
{
    Unique!Transformation transform = get_transform(algo);
    
    //transform.set_key(key);
    transform.start_vec(nonce);
    
    Secure_Vector!ubyte output = input;
    transform.update(output, 0);
    
    return output;
}

unittest
{
    File vec = File("test_data/transform.vec", "r");
    
    size_t fails = run_tests(vec, "Transform", "Output", true,
                     (string[string] m) {
                        atomicOp!"+="(total_tests, 1);
                        return hex_encode(transform_test(m["Transform"],
                                            hex_decode_locked(m["Nonce"]),
                                            hex_decode_locked(m["Key"]),
                                            hex_decode_locked(m["Input"])));
                    });
        
    test_report("transform", total_tests, fails);
}
