/*
* Blinding for public key operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
import botan.reducer;
/**
* Blinding Function Object
*/
class Blinder
{
	public:
		BigInt blind(in BigInt x) const;
		BigInt unblind(in BigInt x) const;

		bool initialized() const { return reducer.initialized(); }

		Blinder() {}

		/**
		* Construct a blinder
		* @param mask the forward (blinding) mask
		* @param inverse_mask the inverse of mask (depends on algo)
		* @param modulus of the group operations are performed in
		*/
		Blinder(in BigInt mask,
				  ref const BigInt inverse_mask,
				  ref const BigInt modulus);

	private:
		Modular_Reducer reducer;
		mutable BigInt e, d;
};