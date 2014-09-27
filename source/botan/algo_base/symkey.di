/*
* OctetString
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/secmem.h>
#include <string>
/**
* Octet String
*/
class OctetString
{
	public:
		/**
		* @return size of this octet string in bytes
		*/
		size_t length() const { return bits.size(); }

		/**
		* @return this object as a SafeVector!byte
		*/
		SafeVector!byte bits_of() const { return bits; }

		/**
		* @return start of this string
		*/
		const byte* begin() const { return &bits[0]; }

		/**
		* @return end of this string
		*/
		const byte* end() const{ return begin() + bits.size(); }

		/**
		* @return this encoded as hex
		*/
		string as_string() const;

		/**
		* XOR the contents of another octet string into this one
		* @param other octet string
		* @return reference to this
		*/
		OctetString& operator^=(in OctetString other);

		/**
		* Force to have odd parity
		*/
		void set_odd_parity();

		/**
		* Create a new OctetString
		* @param str is a hex encoded string
		*/
		OctetString(in string str = "");

		/**
		* Create a new random OctetString
		* @param rng is a random number generator
		* @param len is the desired length in bytes
		*/
		OctetString(class RandomNumberGenerator& rng, size_t len);

		/**
		* Create a new OctetString
		* @param in is an array
		* @param len is the length of in in bytes
		*/
		OctetString(in byte* input, size_t len);

		/**
		* Create a new OctetString
		* @param in a bytestring
		*/
		OctetString(in SafeVector!byte input) : bits(input) {}

		/**
		* Create a new OctetString
		* @param in a bytestring
		*/
		OctetString(in Vector!byte input) : bits(&input[0], &input[input.size()]) {}
	private:
		SafeVector!byte bits;
};

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is equal to y
*/
bool operator==(in OctetString x,
								  const OctetString& y);

/**
* Compare two strings
* @param x an octet string
* @param y an octet string
* @return if x is not equal to y
*/
bool operator!=(in OctetString x,
								  const OctetString& y);

/**
* Concatenate two strings
* @param x an octet string
* @param y an octet string
* @return x concatenated with y
*/
OctetString operator+(in OctetString x,
										  const OctetString& y);

/**
* XOR two strings
* @param x an octet string
* @param y an octet string
* @return x XORed with y
*/
OctetString operator^(in OctetString x,
										  const OctetString& y);/**
* Alternate name for octet string showing intent to use as a key
*/
typedef OctetString SymmetricKey;

/**
* Alternate name for octet string showing intent to use as an IV
*/
typedef OctetString InitializationVector;