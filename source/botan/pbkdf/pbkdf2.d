/*
* PBKDF2
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbkdf.pbkdf2;

import botan.constants;
static if (BOTAN_HAS_PBKDF2):

import botan.pbkdf.pbkdf;
import botan.mac.mac;
import botan.utils.get_byte;
import botan.utils.xor_buf;
import botan.utils.rounding;

/**
* PKCS #5 PBKDF2
*/
final class PKCS5_PBKDF2 : PBKDF
{
public:
	override @property string name() const
	{
		return "PBKDF2(" ~ m_mac.name ~ ")";
	}

	override PBKDF clone() const
	{
		return new PKCS5_PBKDF2(m_mac.clone());
	}

	/*
	* Return a PKCS #5 PBKDF2 derived key
	*/
	override 
	Pair!(size_t, OctetString)
		key_derivation(size_t key_len,
		               in string passphrase,
		               in ubyte* salt, size_t salt_len,
		               size_t iterations,
		               Duration loop_for) const
	{
		if (key_len == 0)
			return Pair(iterations, OctetString());
		
		try
		{
			m_mac.set_key(cast(const ubyte*)(passphrase.data()),
			            passphrase.length);
		}
		catch(Invalid_Key_Length)
		{
			throw new Exception(name ~ " cannot accept passphrases of length " ~ to!string(passphrase.length));
		}
		
		Secure_Vector!ubyte key = Secure_Vector!ubyte(key_len);
		
		ubyte* T = &key[0];
		
		Secure_Vector!ubyte U = Secure_Vector!ubyte(m_mac.output_length);
		
		const size_t blocks_needed = round_up(key_len, m_mac.output_length) / m_mac.output_length;
		
		Duration dur_per_block = loop_for / blocks_needed;
		
		uint counter = 1;
		while(key_len)
		{
			size_t T_size = std.algorithm.min(mac.output_length, key_len);
			
			m_mac.update(salt, salt_len);
			m_mac.update_be(counter);
			m_mac.flushInto(&U[0]);
			
			xor_buf(T, &U[0], T_size);
			
			if (iterations == 0)
			{
				/*
				If no iterations set, run the first block to calibrate based
				on how long hashing takes on whatever machine we're running on.
				*/
				
				const auto start = Clock.currTime();
				
				iterations = 1; // the first iteration we did above
				
				while(true)
				{
					m_mac.update(U);
					m_mac.flushInto(&U[0]);
					xor_buf(T, &U[0], T_size);
					iterations++;
					
					/*
					Only break on relatively 'even' iterations. For one it
					avoids confusion, and likely some broken implementations
					break on getting completely randomly distributed values
					*/
					if (iterations % 10000 == 0)
					{
						auto time_taken = Clock.currTime() - start;
						if (time_taken > dur_per_block)
							break;
					}
				}
			}
			else
			{
				foreach (size_t i; 1 .. iterations)
				{
					m_mac.update(U);
					m_mac.flushInto(&U[0]);
					xor_buf(T, &U[0], T_size);
				}
			}
			
			key_len -= T_size;
			T += T_size;
			++counter;
		}
		
		return Pair(iterations, key);
	}

	/**
	* Create a PKCS #5 instance using the specified message auth code
	* @param mac_fn the MAC object to use as PRF
	*/
	this(MessageAuthenticationCode mac_fn) 
	{
		m_mac = mac_fn;
	}
private:
	Unique!MessageAuthenticationCode m_mac;
}