/*
* ElGamal
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.dl_algo;
import botan.numthry;
import botan.reducer;
import botan.blinding;
import botan.pubkey.pk_ops;
/**
* ElGamal Public Key
*/
class ElGamal_PublicKey : DL_Scheme_PublicKey
{
	public:
		string algo_name() const { return "ElGamal"; }
		DL_Group::Format group_format() const { return DL_Group::ANSI_X9_42; }

		size_t max_input_bits() const { return (group_p().bits() - 1); }

		ElGamal_PublicKey(in AlgorithmIdentifier alg_id,
								in SafeVector!ubyte key_bits) :
			DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
		{}

		ElGamal_PublicKey(in DL_Group group, ref const BigInt y);
	package:
		ElGamal_PublicKey() {}
};

/**
* ElGamal Private Key
*/
class ElGamal_PrivateKey : ElGamal_PublicKey,
												 public abstract DL_Scheme_PrivateKey
{
	public:
		bool check_key(RandomNumberGenerator rng, bool) const;

		ElGamal_PrivateKey(in AlgorithmIdentifier alg_id,
								 in SafeVector!ubyte key_bits,
								 RandomNumberGenerator rng);

		ElGamal_PrivateKey(RandomNumberGenerator rng,
								 const DL_Group& group,
								 ref const BigInt priv_key = 0);
};

/**
* ElGamal encryption operation
*/
class ElGamal_Encryption_Operation : pk_ops.Encryption
{
	public:
		size_t max_input_bits() const { return mod_p.get_modulus().bits() - 1; }

		ElGamal_Encryption_Operation(in ElGamal_PublicKey key);

		SafeVector!ubyte encrypt(in ubyte* msg, size_t msg_len,
											RandomNumberGenerator rng);

	private:
		Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
		Modular_Reducer mod_p;
};

/**
* ElGamal decryption operation
*/
class ElGamal_Decryption_Operation : pk_ops.Decryption
{
	public:
		size_t max_input_bits() const { return mod_p.get_modulus().bits() - 1; }

		ElGamal_Decryption_Operation(in ElGamal_PrivateKey key,
											  RandomNumberGenerator rng);

		SafeVector!ubyte decrypt(in ubyte* msg, size_t msg_len);
	private:
		Fixed_Exponent_Power_Mod powermod_x_p;
		Modular_Reducer mod_p;
		Blinder blinder;
};