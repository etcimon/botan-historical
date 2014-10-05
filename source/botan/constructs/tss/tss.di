/*
* RTSS (threshold secret sharing)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.alloc.secmem;
import botan.hash;
import botan.rng;
import vector;
/**
* A split secret, using the format from draft-mcgrew-tss-03
*/
class RTSS_Share
{
	public:
		/**
		* @param M the number of shares needed to reconstruct
		* @param N the number of shares generated
		* @param secret the secret to split
		* @param secret_len the length of the secret
		* @param identifier the 16 ubyte share identifier
		* @param rng the random number generator to use
		*/
		static Vector!( RTSS_Share )
			split(ubyte M, ubyte N,
					in ubyte* secret, ushort secret_len,
					const ubyte identifier[16],
					RandomNumberGenerator rng);

		/**
		* @param shares the list of shares
		*/
		static SafeVector!ubyte
		  reconstruct(in Vector!( RTSS_Share ) shares);

		RTSS_Share() {}

		/**
		* @param hex_input the share encoded in hexadecimal
		*/
		RTSS_Share(in string hex_input);

		/**
		* @return hex representation
		*/
		string to_string() const;

		/**
		* @return share identifier
		*/
		ubyte share_id() const;

		/**
		* @return size of this share in bytes
		*/
		size_t size() const { return contents.size(); }

		/**
		* @return if this TSS share was initialized or not
		*/
		bool initialized() const { return (contents.size() > 0); }
	private:
		SafeVector!ubyte contents;
};