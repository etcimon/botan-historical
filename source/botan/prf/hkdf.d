/*
* HKDF
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.prf.hkdf;

import botan.mac.mac;
import botan.hash.hash;
/**
* HKDF, see @rfc 5869 for details
*/
class HKDF
{
public:
	this(MessageAuthenticationCode extractor,
		  MessageAuthenticationCode prf) 
	{
		m_extractor = extractor;
		m_prf = prf;
	}

	this(MessageAuthenticationCode prf)
	{
		m_extractor = prf;
		m_prf = m_extractor.clone(); 
	}

	void start_extract(in ubyte* salt, size_t salt_len)
	{
		m_extractor.set_key(salt, salt_len);
	}

	void extract(in ubyte* input, size_t input_len)
	{
		m_extractor.update(input, input_len);
	}

	void finish_extract()
	{
		m_prf.set_key(m_extractor.flush());
	}


	/**
	* Only call after extract
	* @param output_len must be less than 256*hashlen
	*/
	void expand(ubyte* output, size_t output_len,
	            in ubyte* info, size_t info_len)
	{
		if (output_len > m_prf.output_length() * 255)
			throw new Invalid_Argument("HKDF requested output too large");
		
		ubyte counter = 1;
		
		SafeVector!ubyte T;
		
		while(output_len)
		{
			m_prf.update(T);
			m_prf.update(info, info_len);
			m_prf.update(counter++);
			T = m_prf.flush();
			
			const size_t to_write = std.algorithm.min(T.length, output_len);
			copy_mem(&output[0], &T[0], to_write);
			output += to_write;
			output_len -= to_write;
		}
	}


	string name() const
	{
		return "HKDF(" ~ m_prf.name() ~ ")";
	}

	void clear()
	{
		m_extractor.clear();
		m_prf.clear();
	}
private:
	Unique!MessageAuthenticationCode m_extractor;
	Unique!MessageAuthenticationCode m_prf;
};