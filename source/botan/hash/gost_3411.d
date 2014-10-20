/*
* GOST 34.11
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.gost_3411;
import botan.hash.hash;
import botan.block.gost_28147;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.xor_buf;
/**
* GOST 34.11
*/
class GOST_34_11 : HashFunction
{
public:
	string name() const { return "GOST-R-34.11-94" ; }
	size_t output_length() const { return 32; }
	size_t hash_block_size() const { return 32; }
	HashFunction clone() const { return new GOST_34_11; }

	void clear()
	{
		cipher.clear();
		zeroise(sum);
		zeroise(hash);
		count = 0;
		position = 0;
	}

	/**
	* GOST 34.11 Constructor
	*/
	this() 
	{
		cipher = GOST_28147_89_Params("R3411_CryptoPro");
		buffer = 32;
		sum = 32;
		hash = 32;
		count = 0;
		position = 0;
	}
private:
	/**
	* The GOST 34.11 compression function
	*/
	void compress_n(in ubyte* input, size_t blocks)
	{
		for (size_t i = 0; i != blocks; ++i)
		{
			for (ushort j = 0, carry = 0; j != 32; ++j)
			{
				ushort s = sum[j] + input[32*i+j] + carry;
				carry = get_byte(0, s);
				sum[j] = get_byte(1, s);
			}
			
			ubyte[32] S;
			
			ulong[4] U, V;
			load_be(U, &hash[0], 4);
			load_be(V, input + 32*i, 4);
			
			for (size_t j = 0; j != 4; ++j)
			{
				ubyte[32] key;
				
				// P transformation
				for (size_t k = 0; k != 4; ++k)
					for (size_t l = 0; l != 8; ++l)
						key[4*l+k] = get_byte(l, U[k]) ^ get_byte(l, V[k]);
				
				cipher.set_key(key, 32);
				cipher.encrypt(&hash[8*j], S + 8*j);
				
				if (j == 3)
					break;
				
				// A(x)
				ulong A_U = U[0];
				U[0] = U[1];
				U[1] = U[2];
				U[2] = U[3];
				U[3] = U[0] ^ A_U;
				
				if (j == 1) // C_3
				{
					U[0] ^= 0x00FF00FF00FF00FF;
					U[1] ^= 0xFF00FF00FF00FF00;
					U[2] ^= 0x00FFFF00FF0000FF;
					U[3] ^= 0xFF000000FFFF00FF;
				}
				
				// A(A(x))
				ulong AA_V_1 = V[0] ^ V[1];
				ulong AA_V_2 = V[1] ^ V[2];
				V[0] = V[2];
				V[1] = V[3];
				V[2] = AA_V_1;
				V[3] = AA_V_2;
			}
			
			ubyte[32] S2;
			
			// 12 rounds of psi
			S2[ 0] = S[24];
			S2[ 1] = S[25];
			S2[ 2] = S[26];
			S2[ 3] = S[27];
			S2[ 4] = S[28];
			S2[ 5] = S[29];
			S2[ 6] = S[30];
			S2[ 7] = S[31];
			S2[ 8] = S[ 0] ^ S[ 2] ^ S[ 4] ^ S[ 6] ^ S[24] ^ S[30];
			S2[ 9] = S[ 1] ^ S[ 3] ^ S[ 5] ^ S[ 7] ^ S[25] ^ S[31];
			S2[10] = S[ 0] ^ S[ 8] ^ S[24] ^ S[26] ^ S[30];
			S2[11] = S[ 1] ^ S[ 9] ^ S[25] ^ S[27] ^ S[31];
			S2[12] = S[ 0] ^ S[ 4] ^ S[ 6] ^ S[10] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
			S2[13] = S[ 1] ^ S[ 5] ^ S[ 7] ^ S[11] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
			S2[14] = S[ 0] ^ S[ 4] ^ S[ 8] ^ S[12] ^ S[24] ^ S[26] ^ S[28];
			S2[15] = S[ 1] ^ S[ 5] ^ S[ 9] ^ S[13] ^ S[25] ^ S[27] ^ S[29];
			S2[16] = S[ 2] ^ S[ 6] ^ S[10] ^ S[14] ^ S[26] ^ S[28] ^ S[30];
			S2[17] = S[ 3] ^ S[ 7] ^ S[11] ^ S[15] ^ S[27] ^ S[29] ^ S[31];
			S2[18] = S[ 0] ^ S[ 2] ^ S[ 6] ^ S[ 8] ^ S[12] ^ S[16] ^ S[24] ^ S[28];
			S2[19] = S[ 1] ^ S[ 3] ^ S[ 7] ^ S[ 9] ^ S[13] ^ S[17] ^ S[25] ^ S[29];
			S2[20] = S[ 2] ^ S[ 4] ^ S[ 8] ^ S[10] ^ S[14] ^ S[18] ^ S[26] ^ S[30];
			S2[21] = S[ 3] ^ S[ 5] ^ S[ 9] ^ S[11] ^ S[15] ^ S[19] ^ S[27] ^ S[31];
			S2[22] = S[ 0] ^ S[ 2] ^ S[10] ^ S[12] ^ S[16] ^ S[20] ^ S[24] ^ S[28] ^ S[30];
			S2[23] = S[ 1] ^ S[ 3] ^ S[11] ^ S[13] ^ S[17] ^ S[21] ^ S[25] ^ S[29] ^ S[31];
			S2[24] = S[ 0] ^ S[ 6] ^ S[12] ^ S[14] ^ S[18] ^ S[22] ^ S[24] ^ S[26];
			S2[25] = S[ 1] ^ S[ 7] ^ S[13] ^ S[15] ^ S[19] ^ S[23] ^ S[25] ^ S[27];
			S2[26] = S[ 2] ^ S[ 8] ^ S[14] ^ S[16] ^ S[20] ^ S[24] ^ S[26] ^ S[28];
			S2[27] = S[ 3] ^ S[ 9] ^ S[15] ^ S[17] ^ S[21] ^ S[25] ^ S[27] ^ S[29];
			S2[28] = S[ 4] ^ S[10] ^ S[16] ^ S[18] ^ S[22] ^ S[26] ^ S[28] ^ S[30];
			S2[29] = S[ 5] ^ S[11] ^ S[17] ^ S[19] ^ S[23] ^ S[27] ^ S[29] ^ S[31];
			S2[30] = S[ 0] ^ S[ 2] ^ S[ 4] ^ S[12] ^ S[18] ^ S[20] ^ S[28];
			S2[31] = S[ 1] ^ S[ 3] ^ S[ 5] ^ S[13] ^ S[19] ^ S[21] ^ S[29];
			
			xor_buf(S, S2, input + 32*i, 32);
			
			S2[0] = S[0] ^ S[2] ^ S[4] ^ S[6] ^ S[24] ^ S[30];
			S2[1] = S[1] ^ S[3] ^ S[5] ^ S[7] ^ S[25] ^ S[31];
			
			copy_mem(S, S+2, 30);
			S[30] = S2[0];
			S[31] = S2[1];
			
			xor_buf(S, &hash[0], 32);
			
			// 61 rounds of psi
			S2[ 0] = S[ 2] ^ S[ 6] ^ S[14] ^ S[20] ^ S[22] ^ S[26] ^ S[28] ^ S[30];
			S2[ 1] = S[ 3] ^ S[ 7] ^ S[15] ^ S[21] ^ S[23] ^ S[27] ^ S[29] ^ S[31];
			S2[ 2] = S[ 0] ^ S[ 2] ^ S[ 6] ^ S[ 8] ^ S[16] ^ S[22] ^ S[28];
			S2[ 3] = S[ 1] ^ S[ 3] ^ S[ 7] ^ S[ 9] ^ S[17] ^ S[23] ^ S[29];
			S2[ 4] = S[ 2] ^ S[ 4] ^ S[ 8] ^ S[10] ^ S[18] ^ S[24] ^ S[30];
			S2[ 5] = S[ 3] ^ S[ 5] ^ S[ 9] ^ S[11] ^ S[19] ^ S[25] ^ S[31];
			S2[ 6] = S[ 0] ^ S[ 2] ^ S[10] ^ S[12] ^ S[20] ^ S[24] ^ S[26] ^ S[30];
			S2[ 7] = S[ 1] ^ S[ 3] ^ S[11] ^ S[13] ^ S[21] ^ S[25] ^ S[27] ^ S[31];
			S2[ 8] = S[ 0] ^ S[ 6] ^ S[12] ^ S[14] ^ S[22] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
			S2[ 9] = S[ 1] ^ S[ 7] ^ S[13] ^ S[15] ^ S[23] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
			S2[10] = S[ 0] ^ S[ 4] ^ S[ 6] ^ S[ 8] ^ S[14] ^ S[16] ^ S[26] ^ S[28];
			S2[11] = S[ 1] ^ S[ 5] ^ S[ 7] ^ S[ 9] ^ S[15] ^ S[17] ^ S[27] ^ S[29];
			S2[12] = S[ 2] ^ S[ 6] ^ S[ 8] ^ S[10] ^ S[16] ^ S[18] ^ S[28] ^ S[30];
			S2[13] = S[ 3] ^ S[ 7] ^ S[ 9] ^ S[11] ^ S[17] ^ S[19] ^ S[29] ^ S[31];
			S2[14] = S[ 0] ^ S[ 2] ^ S[ 6] ^ S[ 8] ^ S[10] ^ S[12] ^ S[18] ^ S[20] ^ S[24];
			S2[15] = S[ 1] ^ S[ 3] ^ S[ 7] ^ S[ 9] ^ S[11] ^ S[13] ^ S[19] ^ S[21] ^ S[25];
			S2[16] = S[ 2] ^ S[ 4] ^ S[ 8] ^ S[10] ^ S[12] ^ S[14] ^ S[20] ^ S[22] ^ S[26];
			S2[17] = S[ 3] ^ S[ 5] ^ S[ 9] ^ S[11] ^ S[13] ^ S[15] ^ S[21] ^ S[23] ^ S[27];
			S2[18] = S[ 4] ^ S[ 6] ^ S[10] ^ S[12] ^ S[14] ^ S[16] ^ S[22] ^ S[24] ^ S[28];
			S2[19] = S[ 5] ^ S[ 7] ^ S[11] ^ S[13] ^ S[15] ^ S[17] ^ S[23] ^ S[25] ^ S[29];
			S2[20] = S[ 6] ^ S[ 8] ^ S[12] ^ S[14] ^ S[16] ^ S[18] ^ S[24] ^ S[26] ^ S[30];
			S2[21] = S[ 7] ^ S[ 9] ^ S[13] ^ S[15] ^ S[17] ^ S[19] ^ S[25] ^ S[27] ^ S[31];
			S2[22] = S[ 0] ^ S[ 2] ^ S[ 4] ^ S[ 6] ^ S[ 8] ^ S[10] ^ S[14] ^ S[16] ^
				S[18] ^ S[20] ^ S[24] ^ S[26] ^ S[28] ^ S[30];
			S2[23] = S[ 1] ^ S[ 3] ^ S[ 5] ^ S[ 7] ^ S[ 9] ^ S[11] ^ S[15] ^ S[17] ^
				S[19] ^ S[21] ^ S[25] ^ S[27] ^ S[29] ^ S[31];
			S2[24] = S[ 0] ^ S[ 8] ^ S[10] ^ S[12] ^ S[16] ^ S[18] ^ S[20] ^ S[22] ^
				S[24] ^ S[26] ^ S[28];
			S2[25] = S[ 1] ^ S[ 9] ^ S[11] ^ S[13] ^ S[17] ^ S[19] ^ S[21] ^ S[23] ^
				S[25] ^ S[27] ^ S[29];
			S2[26] = S[ 2] ^ S[10] ^ S[12] ^ S[14] ^ S[18] ^ S[20] ^ S[22] ^ S[24] ^
				S[26] ^ S[28] ^ S[30];
			S2[27] = S[ 3] ^ S[11] ^ S[13] ^ S[15] ^ S[19] ^ S[21] ^ S[23] ^ S[25] ^
				S[27] ^ S[29] ^ S[31];
			S2[28] = S[ 0] ^ S[ 2] ^ S[ 6] ^ S[12] ^ S[14] ^ S[16] ^ S[20] ^ S[22] ^ S[26] ^ S[28];
			S2[29] = S[ 1] ^ S[ 3] ^ S[ 7] ^ S[13] ^ S[15] ^ S[17] ^ S[21] ^ S[23] ^ S[27] ^ S[29];
			S2[30] = S[ 2] ^ S[ 4] ^ S[ 8] ^ S[14] ^ S[16] ^ S[18] ^ S[22] ^ S[24] ^ S[28] ^ S[30];
			S2[31] = S[ 3] ^ S[ 5] ^ S[ 9] ^ S[15] ^ S[17] ^ S[19] ^ S[23] ^ S[25] ^ S[29] ^ S[31];
			
			copy_mem(&hash[0], &S2[0], 32);
		}
	}

	/**
	* Hash additional inputs
	*/
	void add_data(in ubyte* input, size_t length)
	{
		count += length;
		
		if (position)
		{
			buffer_insert(buffer, position, input, length);
			
			if (position + length >= hash_block_size())
			{
				compress_n(&buffer[0], 1);
				input += (hash_block_size() - position);
				length -= (hash_block_size() - position);
				position = 0;
			}
		}
		
		const size_t full_blocks = length / hash_block_size();
		const size_t remaining	= length % hash_block_size();
		
		if (full_blocks)
			compress_n(input, full_blocks);
		
		buffer_insert(buffer, position, input + full_blocks * hash_block_size(), remaining);
		position += remaining;
	}

	/**
	* Produce the final GOST 34.11 output
	*/
	void final_result(ubyte* output)
	{
		if (position)
		{
			clear_mem(&buffer[0] + position, buffer.length - position);
			compress_n(&buffer[0], 1);
		}
		
		SafeVector!ubyte length_buf = SafeVector!ubyte(32);
		const ulong bit_count = count * 8;
		store_le(bit_count, &length_buf[0]);
		
		SafeVector!ubyte sum_buf = sum;
		
		compress_n(&length_buf[0], 1);
		compress_n(&sum_buf[0], 1);
		
		copy_mem(output, &hash[0], 32);
		
		clear();
	}

	GOST_28147_89 cipher;
	SafeVector!ubyte buffer, sum, hash;
	size_t position;
	ulong count;
};