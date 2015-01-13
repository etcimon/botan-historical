/*
* Block Cipher Base Class
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.block_cipher;

import botan.constants;
public import botan.algo_base.transform;
public import botan.algo_base.sym_algo;

/**
* This class represents a block cipher object.
*/
interface BlockCipher : SymmetricAlgorithm
{
public:

    /**
    * @return block size of this algorithm
    */
    abstract size_t blockSize() const;

    /**
    * @return native parallelism of this cipher in blocks
    */
    abstract @property size_t parallelism() const;

    /**
    * @return prefererred parallelism of this cipher in bytes
    */
    final size_t parallelBytes() const
    {
        return parallelism * this.blockSize() * BOTAN_BLOCK_CIPHER_PAR_MULT;
    }

    /**
    * Encrypt a block.
    * @param input = The plaintext block to be encrypted as a ubyte array.
    * Must be of length blockSize().
    * @param output = The ubyte array designated to hold the encrypted block.
    * Must be of length blockSize().
    */
    final void encrypt(const(ubyte)* input, ubyte* output)
    { encryptN(input, output, 1); }

    /**
    * Decrypt a block.
    * @param input = The ciphertext block to be decypted as a ubyte array.
    * Must be of length blockSize().
    * @param output = The ubyte array designated to hold the decrypted block.
    * Must be of length blockSize().
    */
    final void decrypt(const(ubyte)* input, ubyte* output)
    { decryptN(input, output, 1); }

    /**
    * Encrypt a block.
    * @param block = the plaintext block to be encrypted
    * Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void encrypt(ubyte* block) { encryptN(cast(const(ubyte)*)block, block, 1); }
    
    /**
    * Decrypt a block.
    * @param block = the ciphertext block to be decrypted
    * Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void decrypt(ubyte* block) { decryptN(cast(const(ubyte)*)block, block, 1); }

    /**
    * Encrypt a block.
    * @param block = the plaintext block to be encrypted
    * Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void encrypt(ref ubyte[] block) 
    in { assert(block.length == this.blockSize()); }
    body { encryptN(block.ptr, block.ptr, 1); }
    
    /**
    * Decrypt a block.
    * @param block = the ciphertext block to be decrypted
    * Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void decrypt(ref ubyte[] block) 
    in { assert(block.length == this.blockSize()); }
    body { decryptN(block.ptr, block.ptr, 1); }

    /**
    * Encrypt one or more blocks
    * @param block = the input/output buffer (multiple of blockSize())
    */
    final void encrypt(int Alloc)(FreeListRef!(VectorImpl!( ubyte, Alloc )) block)
    {
        return encryptN(block.ptr, block.ptr, block.length / this.blockSize());
    }

    /**
    * Decrypt one or more blocks
    * @param block = the input/output buffer (multiple of blockSize())
    */
    final void decrypt(int Alloc)(FreeListRef!(VectorImpl!( ubyte, Alloc )) block)
    {
        return decryptN(block.ptr, block.ptr, block.length / this.blockSize());
    }

    /**
    * Encrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    */
    final void encrypt(int Alloc, int Alloc2)(FreeListRef!(VectorImpl!( ubyte, Alloc )) input,
                                      FreeListRef!(VectorImpl!( ubyte, Alloc2 )) output)
    {
        return encryptN(input.ptr, output.ptr, input.length / this.blockSize());
    }
    
    /**
    * Decrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    */
    final void decrypt(int Alloc, int Alloc2)(FreeListRef!(VectorImpl!( ubyte, Alloc )) input,
                                      FreeListRef!(VectorImpl!( ubyte, Alloc2 )) output)
    {
        return decryptN(input.ptr, output.ptr, input.length / this.blockSize());
    }
    /**
    * Encrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    */
    final void encrypt(ubyte[] input, ref ubyte[] output)
    in { assert(input.length >= this.blockSize()); }
    body {
        return encryptN(input.ptr, output.ptr, input.length / blockSize());
    }
    
    /**
    * Decrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    */
    final void decrypt(ubyte[] input, ref ubyte[] output)
    in { assert(input.length >= this.blockSize()); }
    body {
        return decryptN(input.ptr, output.ptr, input.length / this.blockSize());
    }

    /**
    * Encrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    * @param blocks = the number of blocks to process
    */
    abstract void encryptN(const(ubyte)* input, ubyte* output, size_t blocks);

    /**
    * Decrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    * @param blocks = the number of blocks to process
    */
    abstract void decryptN(const(ubyte)* input, ubyte* output, size_t blocks);

    /**
    * @return new object representing the same algorithm as this
    */
    abstract BlockCipher clone() const;
}

/**
* Represents a block cipher with a single fixed block size
*/ 
abstract class BlockCipherFixedParams(size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1) : BlockCipher, SymmetricAlgorithm
{
public:
    enum { BLOCK_SIZE = BS }
    override size_t blockSize() const { return BS; }

    KeyLengthSpecification keySpec() const
    {
        return KeyLengthSpecification(KMIN, KMAX, KMOD);
    }

	abstract void clear();
	this() { logTrace("__ctor ", name); clear(); }
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.algo_factory.algo_factory;
import botan.codec.hex;
import core.atomic;

shared size_t total_tests;

size_t blockTest(string algo, string key_hex, string in_hex, string out_hex)
{
	logTrace("Block Cipher: ", algo);
    const SecureVector!ubyte key = hexDecodeLocked(key_hex);
    const SecureVector!ubyte pt = hexDecodeLocked(in_hex);
    const SecureVector!ubyte ct = hexDecodeLocked(out_hex);
	logTrace("Fetch algorithm factory");
    AlgorithmFactory af = globalState().algorithmFactory();
    
	logTrace("Fetching providers");
    const auto providers = af.providersOf(algo);
    size_t fails = 0;
    
    if (providers.empty)
        throw new Exception("Unknown block cipher " ~ algo);
    
    foreach (provider; providers[])
    {

        atomicOp!"+="(total_tests, 1);
		logTrace("Fetching block cipher");
		const BlockCipher proto = af.prototypeBlockCipher(algo, provider);
        
        if (!proto)
        {
            logTrace("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!BlockCipher cipher = proto.clone();
        cipher.setKey(key);
        SecureVector!ubyte buf = pt.dup;
        
		logTrace("Encrypting ", buf[]);
        cipher.encrypt(buf);
		logTrace(buf[], " Real");
		logTrace(ct[], " Expected");
        atomicOp!"+="(total_tests, 1);
        if (buf != ct)
        {
            ++fails;
            buf = ct.dup;
        }
		logTrace("Decrypting ", buf[]);
        cipher.decrypt(buf);
		logTrace(buf[], " Real");
		logTrace(pt[], " Expected");

        atomicOp!"+="(total_tests, 1);
        if (buf != pt)
        {
            ++fails;
        }
    }
	logTrace("Finished ", algo, " Fails: ", fails);
	import core.thread;
	import std.datetime;
	Thread.sleep(2.seconds);
    return fails;
}

unittest {
	logTrace("Testing block_cipher.d ...");
    size_t test_bc(string input)
    {
		logTrace("Testing file `" ~ input ~ " ...");
        File vec = File(input, "r");
        return runTestsBb(vec, "BlockCipher", "Out", true,
                          (string[string] m) {
                              return blockTest(m["BlockCipher"], m["Key"], m["In"], m["Out"]);
                          });
    }
    
	logTrace("Running tests ...");
    size_t fails = runTestsInDir("../test_data/block", &test_bc);


    testReport("block_cipher", total_tests, fails);
}
