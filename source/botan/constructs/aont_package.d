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
* @param rng the random number generator to use
* @param cipher the block cipher to use
* @param input the input data buffer
* @param input_len the length of the input data in bytes
* @param output the output data buffer (must be at least
*		  input_len + cipher.BLOCK_SIZE bytes long)
*/
void aont_package(RandomNumberGenerator rng,
                  BlockCipher cipher,
                  in ubyte* input, size_t input_len,
                  ubyte* output)
{
	const size_t BLOCK_SIZE = cipher.block_size;
	
	if (!cipher.valid_keylength(BLOCK_SIZE))
		throw new Invalid_Argument("AONT::package: Invalid cipher");
	
	// The all-zero string which is used both as the CTR IV and as K0
	string all_zeros;
	all_zeros.length = BLOCK_SIZE*2;
	all_zeros.fill('0');
	
	SymmetricKey package_key = SymmetricKey(rng, BLOCK_SIZE);
	
	Pipe pipe = Pipe(new StreamCipher_Filter(new CTR_BE(cipher), package_key));
	
	pipe.process_msg(input, input_len);
	pipe.read(output, pipe.remaining());
	
	// Set K0 (the all zero key)
	cipher.set_key(SymmetricKey(all_zeros));
	
	Secure_Vector!ubyte buf(BLOCK_SIZE);
	
	const size_t blocks =
		(input_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
	
	ubyte* final_block = output + input_len;
	clear_mem(final_block, BLOCK_SIZE);
	
	// XOR the hash blocks into the final block
	for (size_t i = 0; i != blocks; ++i)
	{
		const size_t left = std.algorithm.min(BLOCK_SIZE,
		                                      input_len - BLOCK_SIZE * i);
		
		zeroise(buf);
		copy_mem(&buf[0], output + (BLOCK_SIZE * i), left);
		
		for (size_t j = 0; j != (i).sizeof; ++j)
			buf[BLOCK_SIZE - 1 - j] ^= get_byte((i).sizeof-1-j, i);
		
		cipher.encrypt(&buf[0]);
		
		xor_buf(&final_block[0], &buf[0], BLOCK_SIZE);
	}
	
	// XOR the random package key into the final block
	xor_buf(&final_block[0], package_key.begin(), BLOCK_SIZE);
}

/**
* Rivest's Package Tranform (Inversion)
* @param cipher the block cipher to use
* @param input the input data buffer
* @param input_len the length of the input data in bytes
* @param output the output data buffer (must be at least
*		  input_len - cipher.BLOCK_SIZE bytes long)
*/
void aont_unpackage(BlockCipher cipher,
                    in ubyte* input, size_t input_len,
                    ubyte* output)
{
	const size_t BLOCK_SIZE = cipher.block_size;
	
	if (!cipher.valid_keylength(BLOCK_SIZE))
		throw new Invalid_Argument("AONT::unpackage: Invalid cipher");
	
	if (input_len < BLOCK_SIZE)
		throw new Invalid_Argument("AONT::unpackage: Input too short");
	
	// The all-zero string which is used both as the CTR IV and as K0
	string all_zeros;
	all_zeros.length = BLOCK_SIZE*2;
	all_zeros.fill('0');
	
	cipher.set_key(SymmetricKey(all_zeros));
	
	Secure_Vector!ubyte package_key(BLOCK_SIZE);
	Secure_Vector!ubyte buf(BLOCK_SIZE);
	
	// Copy the package key (masked with the block hashes)
	copy_mem(&package_key[0],
	input + (input_len - BLOCK_SIZE),
	BLOCK_SIZE);
	
	const size_t blocks = ((input_len - 1) / BLOCK_SIZE);
	
	// XOR the blocks into the package key bits
	for (size_t i = 0; i != blocks; ++i)
	{
		const size_t left = std.algorithm.min(BLOCK_SIZE,
		                                      input_len - BLOCK_SIZE * (i+1));
		
		zeroise(buf);
		copy_mem(&buf[0], input + (BLOCK_SIZE * i), left);
		
		for (size_t j = 0; j != (i).sizeof; ++j)
			buf[BLOCK_SIZE - 1 - j] ^= get_byte((i).sizeof-1-j, i);
		
		cipher.encrypt(&buf[0]);
		
		xor_buf(&package_key[0], &buf[0], BLOCK_SIZE);
	}
	
	Pipe pipe = Pipe(new StreamCipher_Filter(new CTR_BE(cipher), package_key));
	
	pipe.process_msg(input, input_len - BLOCK_SIZE);
	
	pipe.read(output, pipe.remaining());


}