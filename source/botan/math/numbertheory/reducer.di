/*
* Modular Reducer
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.numthry;
/**
* Modular Reducer (using Barrett's technique)
*/
class Modular_Reducer
{
	public:
		ref const BigInt get_modulus() const { return modulus; }

		BigInt reduce(in BigInt x) const;

		/**
		* Multiply mod p
		* @param x
		* @param y
		* @return (x * y) % p
		*/
		BigInt multiply(in BigInt x, ref const BigInt y) const
		{ return reduce(x * y); }

		/**
		* Square mod p
		* @param x
		* @return (x * x) % p
		*/
		BigInt square(in BigInt x) const
		{ return reduce(Botan::square(x)); }

		/**
		* Cube mod p
		* @param x
		* @return (x * x * x) % p
		*/
		BigInt cube(in BigInt x) const
		{ return multiply(x, this->square(x)); }

		bool initialized() const { return (mod_words != 0); }

		Modular_Reducer() { mod_words = 0; }
		Modular_Reducer(in BigInt mod);
	private:
		BigInt modulus, modulus_2, mu;
		size_t mod_words;
};