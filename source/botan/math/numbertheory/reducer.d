/*
* Modular Reducer
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.numbertheory.reducer;

import botan.math.numbertheory.numthry;
import botan.math.mp.mp_core;
/**
* Modular Reducer (using Barrett's technique)
*/
struct Modular_Reducer
{
public:
	const ref BigInt get_modulus() const { return modulus; }

	/*
	* Barrett Reduction
	*/
	BigInt reduce(in BigInt x) const
	{
		if (mod_words == 0)
			throw new Invalid_State("Modular_Reducer: Never initalized");
		
		if (x.cmp(modulus, false) < 0)
		{
			if (x.is_negative())
				return x + modulus; // make positive
			return x;
		}
		else if (x.cmp(modulus_2, false) < 0)
		{
			BigInt t1 = x;
			t1.set_sign(BigInt.Positive);
			t1 >>= (MP_WORD_BITS * (mod_words - 1));
			t1 *= mu;
			
			t1 >>= (MP_WORD_BITS * (mod_words + 1));
			t1 *= modulus;
			
			t1.mask_bits(MP_WORD_BITS * (mod_words + 1));
			
			BigInt t2 = x;
			t2.set_sign(BigInt.Positive);
			t2.mask_bits(MP_WORD_BITS * (mod_words + 1));
			
			t2 -= t1;
			
			if (t2.is_negative())
			{
				t2 += BigInt.power_of_2(MP_WORD_BITS * (mod_words + 1));
			}
			
			while(t2 >= modulus)
				t2 -= modulus;
			
			if (x.is_positive())
				return t2;
			else
				return (modulus - t2);
		}
		else
		{
			// too big, fall back to normal division
			return (x % modulus);
		}
	}

	/**
	* Multiply mod p
	* @param x
	* @param y
	* @return (x * y) % p
	*/
	BigInt multiply(in BigInt x, const ref BigInt y) const
	{ return reduce(x * y); }

	/**
	* Square mod p
	* @param x
	* @return (x * x) % p
	*/
	BigInt square(in BigInt x) const
	{ return reduce(square(x)); }

	/**
	* Cube mod p
	* @param x
	* @return (x * x * x) % p
	*/
	BigInt cube(in BigInt x) const
	{ return multiply(x, this.square(x)); }

	bool initialized() const { return (mod_words != 0); }

	this() { mod_words = 0; }
	/*
	* Modular_Reducer Constructor
	*/
	this(in BigInt mod)
	{
		if (mod <= 0)
			throw new Invalid_Argument("Modular_Reducer: modulus must be positive");
		
		modulus = mod;
		mod_words = modulus.sig_words();
		
		modulus_2 = Botan.square(modulus);
		
		mu = BigInt.power_of_2(2 * MP_WORD_BITS * mod_words) / modulus;
	}

private:
	BigInt modulus, modulus_2, mu;
	size_t mod_words;
};

