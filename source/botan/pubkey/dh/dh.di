/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.dl_algo;
import botan.pow_mod;
import botan.blinding;
import botan.pk_ops;
/**
* This class represents Diffie-Hellman public keys.
*/
class DH_PublicKey : public abstract DL_Scheme_PublicKey
{
	public:
		string algo_name() const { return "DH"; }

		Vector!ubyte public_value() const;
		size_t max_input_bits() const { return group_p().bits(); }

		DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }

		DH_PublicKey(in AlgorithmIdentifier alg_id,
						 in SafeVector!ubyte key_bits) :
			DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_42) {}

		/**
		* Construct a public key with the specified parameters.
		* @param grp the DL group to use in the key
		* @param y the public value y
		*/
		DH_PublicKey(in DL_Group grp, ref const BigInt y);
	package:
		DH_PublicKey() {}
};

/**
* This class represents Diffie-Hellman private keys.
*/
class DH_PrivateKey : public DH_PublicKey,
										  public PK_Key_Agreement_Key,
										  public abstract DL_Scheme_PrivateKey
{
	public:
		Vector!ubyte public_value() const;

		/**
		* Load a DH private key
		* @param alg_id the algorithm id
		* @param key_bits the subject public key
		* @param rng a random number generator
		*/
		DH_PrivateKey(in AlgorithmIdentifier alg_id,
						  in SafeVector!ubyte key_bits,
						  RandomNumberGenerator rng);

		/**
		* Construct a private key with predetermined value.
		* @param rng random number generator to use
		* @param grp the group to be used in the key
		* @param x the key's secret value (or if zero, generate a new key)
		*/
		DH_PrivateKey(RandomNumberGenerator rng, const DL_Group& grp,
						  ref const BigInt x = 0);
};

/**
* DH operation
*/
class DH_KA_Operation : public PK_Ops::Key_Agreement
{
	public:
		DH_KA_Operation(in DH_PrivateKey key,
							 RandomNumberGenerator rng);

		SafeVector!ubyte agree(in ubyte* w, size_t w_len);
	private:
		ref const BigInt p;

		Fixed_Exponent_Power_Mod powermod_x_p;
		Blinder blinder;
};