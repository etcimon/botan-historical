/*
* DESX
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.desx;

import botan.constants;
static if (BOTAN_HAS_DES):

import botan.block.des;
import botan.utils.xor_buf;

/**
* DESX
*/
final class DESX : Block_Cipher_Fixed_Params!(8, 24)
{
public:
	/*
	* DESX Encryption
	*/
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		foreach (size_t i; 0 .. blocks)
		{
			xor_buf(output, input, m_K1.ptr, BLOCK_SIZE);
			m_des.encrypt(output);
			xor_buf(output, m_K2.ptr, BLOCK_SIZE);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}

	/*
	* DESX Decryption
	*/
	void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{	
		foreach (size_t i; 0 .. blocks)
		{
			xor_buf(output, input, m_K2.ptr, BLOCK_SIZE);
			m_des.decrypt(output);
			xor_buf(output, m_K1.ptr, BLOCK_SIZE);
			
			input += BLOCK_SIZE;
			output += BLOCK_SIZE;
		}
	}
	void clear()
	{
		m_des.clear();
		zap(m_K1);
		zap(m_K2);
	}

	@property string name() const { return "DESX"; }
	BlockCipher clone() const { return new DESX; }

private:
	/*
	* DESX Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t)
	{
		m_K1.replace(key[0 .. key + 8]);
		m_des.set_key(key + 8, 8);
		m_K2.replace(key[16 .. key + 24]);
	}

	Secure_Vector!ubyte m_K1, m_K2;
	DES m_des;
}
