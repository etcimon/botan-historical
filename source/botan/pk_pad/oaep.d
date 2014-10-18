/*
* OAEP
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.oaep;

import botan.pk_pad.eme;
import botan.kdf.kdf;
import botan.hash.hash;
import botan.pk_pad.mgf1;
import botan.utils.mem_ops;

/**
* OAEP (called EME1 in IEEE 1363 and in earlier versions of the library)
*/
class OAEP : EME
{
public:
	/*
	* Return the max input size for a given key size
	*/
	size_t maximum_input_size(size_t keybits) const
	{
		if (keybits / 8 > 2*m_Phash.size() + 1)
			return ((keybits / 8) - 2*m_Phash.size() - 1);
		else
			return 0;
	}


	/**
	* @param hash object to use for hashing (takes ownership)
	* @param P an optional label. Normally empty.
	*/
	this(HashFunction hash, in string P = "")
	{
		m_hash = hash;
		m_Phash = m_hash.process(P);
	}
private:
	/*
	* OAEP Pad Operation
	*/
	SafeVector!ubyte pad(in ubyte* input, size_t in_length,
	                     size_t key_length,
	                     RandomNumberGenerator rng) const
	{
		key_length /= 8;
		
		if (key_length < in_length + 2*m_Phash.size() + 1)
			throw new Invalid_Argument("OAEP: Input is too large");
		
		SafeVector!ubyte output = SafeVector!ubyte(key_length);
		
		rng.randomize(&output[0], m_Phash.size());
		
		buffer_insert(output, m_Phash.size(), &m_Phash[0], m_Phash.size());
		output[output.size() - in_length - 1] = 0x01;
		buffer_insert(output, output.size() - in_length, input, in_length);
		
		mgf1_mask(*m_hash,
		          &output[0], m_Phash.size(),
		&output[m_Phash.size()], output.size() - m_Phash.size());
		
		mgf1_mask(*m_hash,
		          &output[m_Phash.size()], output.size() - m_Phash.size(),
		&output[0], m_Phash.size());
		
		return output;
	}

	/*
	* OAEP Unpad Operation
	*/
	SafeVector!ubyte unpad(in ubyte* input, size_t in_length,
	                       size_t key_length) const
	{
		/*
		Must be careful about error messages here; if an attacker can
		distinguish them, it is easy to use the differences as an oracle to
		find the secret key, as described in "A Chosen Ciphertext Attack on
		RSA Optimal Asymmetric Encryption Padding (OAEP) as Standardized in
		PKCS #1 v2.0", James Manger, Crypto 2001

		Also have to be careful about timing attacks! Pointed out by Falko
		Strenzke.
		*/
		
		key_length /= 8;
		
		// Invalid input: truncate to zero length input, causing later
		// checks to fail
		if (in_length > key_length)
			in_length = 0;
		
		SafeVector!ubyte input = SafeVector!ubyte(key_length);
		buffer_insert(input, key_length - in_length, input, in_length);
		
		mgf1_mask(*m_hash,
		          &input[m_Phash.size()], input.size() - m_Phash.size(),
		&input[0], m_Phash.size());
		
		mgf1_mask(*m_hash,
		          &input[0], m_Phash.size(),
		&input[m_Phash.size()], input.size() - m_Phash.size());
		
		bool waiting_for_delim = true;
		bool bad_input = false;
		size_t delim_idx = 2 * m_Phash.size();
		
		/*
		* GCC 4.5 on x86-64 compiles this in a way that is still vunerable
		* to timing analysis. Other compilers, or GCC on other platforms,
		* may or may not.
		*/
		for (size_t i = delim_idx; i < input.size(); ++i)
		{
			const bool zero_p = !input[i];
			const bool one_p = input[i] == 0x01;
			
			const bool add_1 = waiting_for_delim && zero_p;
			
			bad_input |= waiting_for_delim && !(zero_p || one_p);
			
			delim_idx += add_1;
			
			waiting_for_delim &= zero_p;
		}
		
		// If we never saw any non-zero ubyte, then it's not valid input
		bad_input |= waiting_for_delim;
		
		bad_input |= !same_mem(&input[m_Phash.size()], &m_Phash[0], m_Phash.size());
		
		if (bad_input)
			throw new Decoding_Error("Invalid OAEP encoding");
		
		return SafeVector!ubyte(&input[delim_idx + 1], &input[input.size()]);
	}

	SafeVector!ubyte m_Phash;
	Unique!HashFunction m_hash;
};