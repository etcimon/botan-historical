/*
* Rivest's Package Tranform
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.aont_package;

import botan.block.block_cipher;
import botan.rng.rng;
import botan.filters.filters;
import botan.stream.ctr;
import botan.utils.get_byte;
import botan.utils.xor_buf;
import botan.algo_base.symkey;

/**
* Rivest's Package Tranform
* @param rng = the random number generator to use
* @param cipher = the block cipher to use
* @param input = the input data buffer
* @param input_len = the length of the input data in bytes
* @param output = the output data buffer (must be at least
*          input_len + cipher.BLOCK_SIZE bytes long)
*/
void aontPackage(RandomNumberGenerator rng,
                  BlockCipher cipher,
                  in ubyte* input, size_t input_len,
                  ubyte* output)
{
    const size_t BLOCK_SIZE = cipher.block_size;
    
    if (!cipher.validKeylength(BLOCK_SIZE))
        throw new InvalidArgument("AONT::package: Invalid cipher");
    
    // The all-zero string which is used both as the CTR IV and as K0
    string all_zeros;
    all_zeros.length = BLOCK_SIZE*2;
    all_zeros.fill('0');
    
    SymmetricKey package_key = SymmetricKey(rng, BLOCK_SIZE);
    
    Pipe pipe = Pipe(new StreamCipher_Filter(new CTR_BE(cipher), package_key));
    
    pipe.processMsg(input, input_len);
    pipe.read(output, pipe.remaining());
    
    // Set K0 (the all zero key)
    cipher.setKey(SymmetricKey(all_zeros));
    
    SecureVector!ubyte buf = SecureVector!ubyte(BLOCK_SIZE);

    const size_t blocks = (input_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    
    ubyte* final_block = output + input_len;
    clear_mem(final_block, BLOCK_SIZE);
    
    // XOR the hash blocks into the final block
    foreach (size_t i; 0 .. blocks)
    {
        const size_t left = std.algorithm.min(BLOCK_SIZE, input_len - BLOCK_SIZE * i);
        
        zeroise(buf);
        copyMem(buf.ptr, output + (BLOCK_SIZE * i), left);
        
        for (size_t j = 0; j != i.sizeof; ++j)
            buf[BLOCK_SIZE - 1 - j] ^= get_byte((i).sizeof-1-j, i);
        
        cipher.encrypt(buf.ptr);
        
        xor_buf(final_block.ptr, buf.ptr, BLOCK_SIZE);
    }
    
    // XOR the random package key into the final block
    xor_buf(final_block.ptr, package_key.ptr, BLOCK_SIZE);
}

/**
* Rivest's Package Tranform (Inversion)
* @param cipher = the block cipher to use
* @param input = the input data buffer
* @param input_len = the length of the input data in bytes
* @param output = the output data buffer (must be at least
*          input_len - cipher.BLOCK_SIZE bytes long)
*/
void aontUnpackage(BlockCipher cipher,
                    in ubyte* input, size_t input_len,
                    ubyte* output)
{
    const size_t BLOCK_SIZE = cipher.block_size;
    
    if (!cipher.validKeylength(BLOCK_SIZE))
        throw new InvalidArgument("AONT::unpackage: Invalid cipher");
    
    if (input_len < BLOCK_SIZE)
        throw new InvalidArgument("AONT::unpackage: Input too short");
    
    // The all-zero string which is used both as the CTR IV and as K0
    string all_zeros;
    all_zeros.length = BLOCK_SIZE*2;
    all_zeros.fill('0');
    
    cipher.setKey(SymmetricKey(all_zeros));
    
    SecureVector!ubyte package_key = SecureVector!ubyte(BLOCK_SIZE);
    SecureVector!ubyte buf = SecureVector!ubyte(BLOCK_SIZE);
    
    // Copy the package key (masked with the block hashes)
    copyMem(package_key.ptr, input + (input_len - BLOCK_SIZE), BLOCK_SIZE);
    
    const size_t blocks = ((input_len - 1) / BLOCK_SIZE);
    
    // XOR the blocks into the package key bits
    foreach (size_t i; 0 .. blocks)
    {
        const size_t left = std.algorithm.min(BLOCK_SIZE,
                                              input_len - BLOCK_SIZE * (i+1));
        
        zeroise(buf);
        copyMem(buf.ptr, input + (BLOCK_SIZE * i), left);
        
        for (size_t j = 0; j != (i).sizeof; ++j)
            buf[BLOCK_SIZE - 1 - j] ^= get_byte((i).sizeof-1-j, i);
        
        cipher.encrypt(buf.ptr);
        
        xor_buf(package_key.ptr, buf.ptr, BLOCK_SIZE);
    }
    
    Pipe pipe = Pipe(new StreamCipher_Filter(new CTR_BE(cipher), package_key));
    
    pipe.processMsg(input, input_len - BLOCK_SIZE);
    
    pipe.read(output, pipe.remaining());


}