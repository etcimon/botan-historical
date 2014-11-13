/*
* The Skein-512 hash function
* (C) 2009,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.skein_512;

import botan.constants;
static if (BOTAN_HAS_SKEIN_512):

import botan.hash.hash;
import botan.block.threefish;
// import string;
import memory;
import botan.utils.loadstor;
import botan.utils.parsing;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.utils.types;
import std.algorithm;

/**
* Skein-512, a SHA-3 candidate
*/
final class Skein_512 : HashFunction
{
public:
	/**
	* @param m_output_bits the output size of Skein in bits
	* @param arg_personalization is a string that will paramaterize the
	* hash output
	*/
	this(size_t m_output_bits = 512,
	     in string arg_personalization = "") 
	{
		m_personalization = arg_personalization;
		m_output_bits = arg_output_bits;
		m_threefish = new Threefish_512;
		m_T = 2;
		m_buffer = 64; 
		m_buf_pos = 0;

		if (m_output_bits == 0 || m_output_bits % 8 != 0 || m_output_bits > 512)
			throw new Invalid_Argument("Bad output bits size for Skein-512");
		
		initial_block();
	}

	override @property size_t hash_block_size() const { return 64; }
	@property size_t output_length() const { return m_output_bits / 8; }

	HashFunction clone() const
	{
		return new Skein_512(m_output_bits, m_personalization);
	}

	@property string name() const
	{
		if (m_personalization != "")
			return "Skein-512(" ~ to!string(m_output_bits) ~ "," ~
				m_personalization ~ ")";
		return "Skein-512(" ~ to!string(m_output_bits) ~ ")";
	}

	void clear()
	{
		zeroise(m_buffer);
		m_buf_pos = 0;
		
		initial_block();
	}

private:
	enum type_code {
		SKEIN_KEY = 0,
		SKEIN_CONFIG = 4,
		SKEIN_PERSONALIZATION = 8,
		SKEIN_PUBLIC_KEY = 12,
		SKEIN_KEY_IDENTIFIER = 16,
		SKEIN_NONCE = 20,
		SKEIN_MSG = 48,
		SKEIN_OUTPUT = 63
	}

	void add_data(in ubyte* input, size_t length)
	{
		if (length == 0)
			return;
		
		if (m_buf_pos)
		{
			buffer_insert(m_buffer, m_buf_pos, input, length);
			if (m_buf_pos + length > 64)
			{
				ubi_512(&m_buffer[0], m_buffer.length);
				
				input += (64 - m_buf_pos);
				length -= (64 - m_buf_pos);
				m_buf_pos = 0;
			}
		}
		
		const size_t full_blocks = (length - 1) / 64;
		
		if (full_blocks)
			ubi_512(input, 64*full_blocks);
		
		length -= full_blocks * 64;
		
		buffer_insert(m_buffer, m_buf_pos, input + full_blocks * 64, length);
		m_buf_pos += length;
	}

	void final_result(ubyte* output)
	{
		m_T[1] |= ((cast(ulong)1) << 63); // final block flag
		
		foreach (size_t i; m_buf_pos .. m_buffer.length)
			m_buffer[i] = 0;
		
		ubi_512(&m_buffer[0], m_buf_pos);
		
		const ubyte[8] counter;
		
		reset_tweak(type_code.SKEIN_OUTPUT, true);
		ubi_512(counter, (counter).sizeof);
		
		const size_t out_bytes = m_output_bits / 8;
		
		foreach (size_t i; 0 .. out_bytes)
			output[i] = get_byte(7-i%8, m_threefish.m_K[i/8]);
		
		m_buf_pos = 0;
		initial_block();
	}

	void ubi_512(in ubyte* msg, size_t msg_len)
	{
		Secure_Vector!ulong M = Secure_Vector!ulong(8);
		
		do
		{
			const size_t to_proc = std.algorithm.min(msg_len, 64);
			m_T[0] += to_proc;
			
			load_le(&M[0], msg, to_proc / 8);
			
			if (to_proc % 8)
			{
				foreach (size_t j; 0 .. (to_proc % 8))
					M[to_proc/8] |= cast(ulong)(msg[8*(to_proc/8)+j]) << (8*j);
			}
			
			m_threefish.skein_feedfwd(M, m_T);
			
			// clear first flag if set
			m_T[1] &= ~(cast(ulong)(1) << 62);
			
			msg_len -= to_proc;
			msg += to_proc;
		} while(msg_len);
	}


	void initial_block()
	{
		const ubyte[64] zeros;
		
		m_threefish.set_key(zeros, (zeros).sizeof);
		
		// ASCII("SHA3") followed by version (0x0001) code
		ubyte[32] config_str = [0x53, 0x48, 0x41, 0x33, 0x01, 0x00, 0 ];
		store_le(uint(m_output_bits), config_str + 8);
		
		reset_tweak(type_code.SKEIN_CONFIG, true);
		ubi_512(config_str, (config_str).sizeof);
		
		if (m_personalization != "")
		{
			/*
			  This is a limitation of this implementation, and not of the
			  algorithm specification. Could be fixed relatively easily, but
			  doesn't seem worth the trouble.
			*/
			if (m_personalization.length > 64)
				throw new Invalid_Argument("Skein m_personalization must be less than 64 bytes");
			
			const ubyte* bits = cast(const ubyte*)(m_personalization.data());
			reset_tweak(type_code.SKEIN_PERSONALIZATION, true);
			ubi_512(bits, m_personalization.length);
		}
		
		reset_tweak(type_code.SKEIN_MSG, false);
	}

	void reset_tweak(type_code type, bool fin)
	{
		m_T[0] = 0;
		
		m_T[1] = (cast(ulong)(type) << 56) |
			(cast(ulong)(1) << 62) |
				(cast(ulong)(fin) << 63);
	}

	string m_personalization;
	size_t m_output_bits;

	Unique!Threefish_512 m_threefish;
	Secure_Vector!ulong m_T;
	Secure_Vector!ubyte m_buffer;
	size_t m_buf_pos;
}
