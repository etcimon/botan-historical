/*
* Block Cipher Base Class
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.block_cipher;

import botan.algo_base.sym_algo;

/**
* This class represents a block cipher object.
*/
class BlockCipher : SymmetricAlgorithm
{
public:

    /**
    * @return block size of this algorithm
    */
    abstract @property size_t blockSize() const;

    /**
    * @return native parallelism of this cipher in blocks
    */
    abstract @property size_t parallelism() const { return 1; }

    /**
    * @return prefererred parallelism of this cipher in bytes
    */
    final size_t parallelBytes() const
    {
        return parallelism * this.block_size * BOTAN_BLOCK_CIPHER_PAR_MULT;
    }

    /**
    * Encrypt a block.
    * @param input = The plaintext block to be encrypted as a ubyte array.
    * Must be of length blockSize().
    * @param output = The ubyte array designated to hold the encrypted block.
    * Must be of length blockSize().
    */
    final void encrypt(ubyte* input, ubyte* output) const
    { encrypt_n(input, output, 1); }

    /**
    * Decrypt a block.
    * @param input = The ciphertext block to be decypted as a ubyte array.
    * Must be of length blockSize().
    * @param output = The ubyte array designated to hold the decrypted block.
    * Must be of length blockSize().
    */
    final void decrypt(ubyte* input, ubyte* output) const
    { decrypt_n(input, output, 1); }

    /**
    * Encrypt a block.
    * @param block = the plaintext block to be encrypted
    * Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void encrypt(ubyte* block) const { encrypt_n(block, block, 1); }
    
    /**
    * Decrypt a block.
    * @param block = the ciphertext block to be decrypted
    * Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void decrypt(ubyte* block) const { decrypt_n(block, block, 1); }

    /**
    * Encrypt a block.
    * @param block = the plaintext block to be encrypted
    * Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void encrypt(ref ubyte[] block) const 
    in { assert(block.length == this.block_size); }
    body { encrypt_n(block.ptr, block.ptr, 1); }
    
    /**
    * Decrypt a block.
    * @param block = the ciphertext block to be decrypted
    * Must be of length blockSize(). Will hold the result when the function
    * has finished.
    */
    final void decrypt(ref ubyte[] block) const 
    in { assert(block.length == this.block_size); }
    body { decrypt_n(block.ptr, block.ptr, 1); }

    /**
    * Encrypt one or more blocks
    * @param block = the input/output buffer (multiple of blockSize())
    */
    final void encrypt(Alloc)(Vector!( ubyte, Alloc ) block) const
    {
        return encrypt_n(block.ptr, block.ptr, block.length / this.block_size);
    }

    /**
    * Decrypt one or more blocks
    * @param block = the input/output buffer (multiple of blockSize())
    */
    final void decrypt(Alloc)(ref Vector!( ubyte, Alloc ) block) const
    {
        return decrypt_n(block.ptr, block.ptr, block.length / this.block_size);
    }

    /**
    * Encrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    */
    final void encrypt(Alloc, Alloc2)(in Vector!( ubyte, Alloc ) input,
                                      ref Vector!( ubyte, Alloc2 ) output) const
    {
        return encrypt_n(input.ptr, output.ptr, input.length / this.block_size);
    }
    
    /**
    * Decrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    */
    final void decrypt(Alloc, Alloc2)(in Vector!( ubyte, Alloc ) input,
                                      ref Vector!( ubyte, Alloc2 ) output) const
    {
        return decrypt_n(input.ptr, output.ptr, input.length / this.block_size);
    }
    /**
    * Encrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    */
    final void encrypt(in ubyte[] input,
                       ref ubyte[] output) const
    in { assert(input.length >= this.block_size); }
    body {
        return encrypt_n(input.ptr, output.ptr, input.length / blockSize());
    }
    
    /**
    * Decrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    */
    final void decrypt(in ubyte[] input,
                       ref ubyte[] output) const
    in { assert(input.length >= this.block_size); }
    body {
        return decrypt_n(input.ptr, output.ptr, input.length / this.block_size);
    }

    /**
    * Encrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    * @param blocks = the number of blocks to process
    */
    abstract void encryptN(ubyte* input, ubyte* output,
                            size_t blocks) const;

    /**
    * Decrypt one or more blocks
    * @param input = the input buffer (multiple of blockSize())
    * @param output = the output buffer (same size as input)
    * @param blocks = the number of blocks to process
    */
    abstract void decryptN(ubyte* input, ubyte* output,
                            size_t blocks) const;

    /**
    * @return new object representing the same algorithm as this
    */
    abstract BlockCipher clone() const;
}

/**
* Represents a block cipher with a single fixed block size
*/
class BlockCipherFixedParams(size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1) : BlockCipher
{
    public:
        enum { BLOCK_SIZE = BS }
        @property size_t blockSize() const { return BS; }

        KeyLengthSpecification keySpec() const
        {
            return Key_Length_Specification(KMIN, KMAX, KMOD);
        }
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.algo_factory.algo_factory;
import botan.codec.hex;

__gshared size_t total_tests;

size_t blockTest(string algo, string key_hex, string in_hex, string out_hex)
{
    const SecureVector!ubyte key = hexDecodeLocked(key_hex);
    const SecureVector!ubyte pt = hexDecodeLocked(in_hex);
    const SecureVector!ubyte ct = hexDecodeLocked(out_hex);
    
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto providers = af.providers_of(algo);
    size_t fails = 0;
    
    if (providers.empty)
        throw new Exception("Unknown block cipher " ~ algo);
    
    foreach (provider; providers)
    {

        atomicOp!"+="(total_tests, 1);
        const BlockCipher proto = af.prototypeBlockCipher(algo, provider);
        
        if (!proto)
        {
            writeln("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!BlockCipher cipher = proto.clone();
        cipher.setKey(key);
        SecureVector!ubyte buf = pt;
        
        cipher.encrypt(buf);

        atomicOp!"+="(total_tests, 1);
        if (buf != ct)
        {
            writeln(algo ~ " " ~ provider ~ " enc " ~ hexEncode(buf) ~ " != " ~ out_hex);
            ++fails;
            buf = ct;
        }
        
        cipher.decrypt(buf);

        atomicOp!"+="(total_tests, 1);
        if (buf != pt)
        {
            writeln(algo ~ " " ~ provider ~ " dec " ~ hexEncode(buf) ~ " != " ~ out_hex);
            ++fails;
        }
    }
    
    return fails;
}

unittest {
    auto test_bc = (string input)
    {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "BlockCipher", "Out", true,
                            (string[string] m) {
                                return blockTest(m["BlockCipher"], m["Key"], m["In"], m["Out"]);
                            });
    };
    
    size_t fails = runTestsInDir("test_data/block", test_bc);


    testReport("block_cipher", total_tests, fails);
}
