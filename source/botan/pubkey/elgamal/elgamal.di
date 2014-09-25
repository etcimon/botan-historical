/*
* ElGamal
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/dl_algo.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/blinding.h>
#include <botan/pk_ops.h>
/**
* ElGamal Public Key
*/
class ElGamal_PublicKey : public abstract DL_Scheme_PublicKey
{
	public:
		string algo_name() const { return "ElGamal"; }
		DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }

		size_t max_input_bits() const { return (group_p().bits() - 1); }

		ElGamal_PublicKey(in AlgorithmIdentifier alg_id,
								in SafeVector!byte key_bits) :
			DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
		{}

		ElGamal_PublicKey(in DL_Group group, const BigInt& y);
	protected:
		ElGamal_PublicKey() {}
};

/**
* ElGamal Private Key
*/
class ElGamal_PrivateKey : public ElGamal_PublicKey,
												 public abstract DL_Scheme_PrivateKey
{
	public:
		bool check_key(RandomNumberGenerator& rng, bool) const;

		ElGamal_PrivateKey(in AlgorithmIdentifier alg_id,
								 in SafeVector!byte key_bits,
								 RandomNumberGenerator& rng);

		ElGamal_PrivateKey(RandomNumberGenerator& rng,
								 const DL_Group& group,
								 const BigInt& priv_key = 0);
};

/**
* ElGamal encryption operation
*/
class ElGamal_Encryption_Operation : public PK_Ops::Encryption
{
	public:
		size_t max_input_bits() const { return mod_p.get_modulus().bits() - 1; }

		ElGamal_Encryption_Operation(in ElGamal_PublicKey key);

		SafeVector!byte encrypt(in byte[] msg, size_t msg_len,
											RandomNumberGenerator& rng);

	private:
		Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
		Modular_Reducer mod_p;
};

/**
* ElGamal decryption operation
*/
class ElGamal_Decryption_Operation : public PK_Ops::Decryption
{
	public:
		size_t max_input_bits() const { return mod_p.get_modulus().bits() - 1; }

		ElGamal_Decryption_Operation(in ElGamal_PrivateKey key,
											  RandomNumberGenerator& rng);

		SafeVector!byte decrypt(in byte[] msg, size_t msg_len);
	private:
		Fixed_Exponent_Power_Mod powermod_x_p;
		Modular_Reducer mod_p;
		Blinder blinder;
};