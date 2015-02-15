/*
* Transformations of data
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.algo_base.transform;

import memutils.vector;
import botan.algo_base.key_spec;
import botan.utils.exceptn;
import botan.algo_base.symkey;
import botan.utils.types;
import botan.constants;

/**
* Interface for general transformations on data
*/
interface Transformation
{
public:
    /**
    * Begin processing a message.
    * @param nonce = the per message nonce
    */    
	final SecureVector!ubyte startVec(Alloc)(auto const ref RefCounted!(Vector!( ubyte, Alloc ), Alloc) nonce)
	{
		return start(nonce.ptr, nonce.length);
	}

	final SecureVector!ubyte startVec(Alloc)(auto const ref Vector!( ubyte, Alloc ) nonce)
	{
		return start(nonce.ptr, nonce.length);
	}

    /**
    * Begin processing a message.
    * @param nonce = the per message nonce
    * @param nonce_len = length of nonce
    */
    SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len);

    /**
    * Process some data. Input must be in size updateGranularity() ubyte blocks.
    * @param blocks = in/out paramter which will possibly be resized
    * @param offset = an offset into blocks to begin processing
    */
    void update(ref SecureVector!ubyte blocks, size_t offset = 0);

    /**
    * Complete processing of a message.
    *
    * @param final_block = in/out parameter which must be at least
    *          minimumFinalSize() bytes, and will be set to any final output
    * @param offset = an offset into final_block to begin processing
    */
    void finish(ref SecureVector!ubyte final_block, size_t offset = 0);

    /**
    * Returns the size of the output if this transform is used to process a
    * message with input_length bytes. Will throw new if unable to give a precise
    * answer.
    */
    size_t outputLength(size_t input_length) const;

    /**
    * @return size of required blocks to update
    */
    size_t updateGranularity() const;

    /**
    * @return required minimium size to finalize() - may be any
    *            length larger than this.
    */
    size_t minimumFinalSize() const;

    /**
    * Return the default size for a nonce
    */
    size_t defaultNonceLength() const;

    /**
    * Return true iff nonce_len is a valid length for the nonce
    */
    bool validNonceLength(size_t nonce_len) const;

    /**
    * Return some short name describing the provider of this tranformation.
    * Useful in cases where multiple implementations are available (eg,
    * different implementations of AES). Default "core" is used for the
    * 'standard' implementation included in the library.
    */
    string provider() const;

    @property string name() const;

    void clear();
}

class KeyedTransform : Transformation
{
public:
    /**
    * @return object describing limits on key size
    */
    abstract KeyLengthSpecification keySpec() const;

    /**
    * Check whether a given key length is valid for this algorithm.
    * @param length = the key length to be checked.
    * @return true if the key length is valid.
    */
    final bool validKeylength(size_t length) const
    {
        return keySpec().validKeylength(length);
    }

	final void setKey(Alloc)(in RefCounted!(Vector!( ubyte, Alloc ), Alloc) key)
	{
		setKey(key.ptr, key.length);
	}

	final void setKey(Alloc)(const ref Vector!( ubyte, Alloc ) key)
	{
		setKey(key.ptr, key.length);
	}

    final void setKey(in SymmetricKey key)
    {
        setKey(key.ptr, key.length);
    }

    /**
    * Set the symmetric key of this transform
    * @param key = contains the key material
    * @param length = in bytes of key param
    */
    final void setKey(const(ubyte)* key, size_t length)
    {
        if (!validKeylength(length))
            throw new InvalidKeyLength(name, length);
        keySchedule(key, length);
    }

protected:

    abstract void keySchedule(const(ubyte)* key, size_t length);
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;

shared size_t total_tests;

Transformation getTransform(string algo)
{
    throw new Exception("Unknown transform " ~ algo);
}

SecureVector!ubyte transformTest(string algo,
                                 in SecureVector!ubyte nonce,
                                 in SecureVector!ubyte /*key*/,
                                 in SecureVector!ubyte input)
{
    Unique!Transformation transform = getTransform(algo);

    //transform.setKey(key);
    transform.startVec(nonce);
    
    SecureVector!ubyte output = input.dup;
    transform.update(output, 0);
    
    return output;
}

static if (!SKIP_TRANSFORM_TEST) unittest
{
    logDebug("Testing transform.d ...");
    File vec = File("../test_data/transform.vec", "r");
    
    size_t fails = runTests(vec, "Transform", "Output", true,
	     (ref HashMap!(string, string) m) {
	        atomicOp!"+="(total_tests, 1);
	        return hexEncode(transformTest(m["Transform"],
	                            hexDecodeLocked(m["Nonce"]),
	                            hexDecodeLocked(m["Key"]),
	                            hexDecodeLocked(m["Input"])));
	    });

    testReport("transform", total_tests, fails);
}
