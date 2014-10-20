/*
* Blinding for public key operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.blinding;

import botan.math.bigint.bigint;
import botan.math.numbertheory.reducer;
import botan.math.numbertheory.numthry;

/**
* Blinding Function Object
*/
struct Blinder
{
public:
	/*
	* Blind a number
	*/
	BigInt blind(in BigInt i)
	{
		if (!reducer.initialized())
			return i;
		
		e = reducer.square(e);
		d = reducer.square(d);
		return reducer.multiply(i, e);
	}

	/*
	* Unblind a number
	*/
	BigInt unblind(in BigInt i) const
	{
		if (!reducer.initialized())
			return i;
		return reducer.multiply(i, d);
	}

	bool initialized() const { return reducer.initialized(); }

	this() {}

	/**
	* Construct a blinder
	* @param mask the forward (blinding) mask
	* @param inverse_mask the inverse of mask (depends on algo)
	* @param modulus of the group operations are performed in
	*/
	this(in BigInt e, const ref BigInt d, const ref BigInt n)
	{
		if (e < 1 || d < 1 || n < 1)
			throw new Invalid_Argument("Blinder: Arguments too small");
		
		reducer = Modular_Reducer(n);
		this.e = e;
		this.d = d;
	}

private:
	Modular_Reducer reducer;
	BigInt e, d;
};