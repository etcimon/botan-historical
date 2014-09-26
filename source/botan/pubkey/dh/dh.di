/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/dl_algo.h>
#include <botan/pow_mod.h>
#include <botan/blinding.h>
#include <botan/pk_ops.h>
/**
* This class represents Diffie-Hellman public keys.
*/
class DH_PublicKey : public abstract DL_Scheme_PublicKey
{
	public:
		string algo_name() const { return "DH"; }

		Vector!( byte ) public_value() const;
		size_t max_input_bits() const { return group_p().bits(); }

		DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }

		DH_PublicKey(in AlgorithmIdentifier alg_id,
						 in SafeVector!byte key_bits) :
			DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_42) {}

		/**
		* Construct a public key with the specified parameters.
		* @param grp the DL group to use in the key
		* @param y the public value y
		*/
		DH_PublicKey(in DL_Group grp, const BigInt& y);
	protected:
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
		Vector!( byte ) public_value() const;

		/**
		* Load a DH private key
		* @param alg_id the algorithm id
		* @param key_bits the subject public key
		* @param rng a random number generator
		*/
		DH_PrivateKey(in AlgorithmIdentifier alg_id,
						  in SafeVector!byte key_bits,
						  RandomNumberGenerator& rng);

		/**
		* Construct a private key with predetermined value.
		* @param rng random number generator to use
		* @param grp the group to be used in the key
		* @param x the key's secret value (or if zero, generate a new key)
		*/
		DH_PrivateKey(RandomNumberGenerator& rng, const DL_Group& grp,
						  const BigInt& x = 0);
};

/**
* DH operation
*/
class DH_KA_Operation : public PK_Ops::Key_Agreement
{
	public:
		DH_KA_Operation(in DH_PrivateKey key,
							 RandomNumberGenerator& rng);

		SafeVector!byte agree(in byte* w, size_t w_len);
	private:
		const BigInt& p;

		Fixed_Exponent_Power_Mod powermod_x_p;
		Blinder blinder;
};