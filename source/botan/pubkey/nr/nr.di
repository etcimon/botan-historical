/*
* Nyberg-Rueppel
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pubkey.algo.dl_algo;
import botan.pubkey.pk_ops;
import botan.math.numbertheory.numthry;
import botan.math.numbertheory.reducer;
/**
* Nyberg-Rueppel Public Key
*/
class NR_PublicKey : DL_Scheme_PublicKey
{
	public:
		string algo_name() const { return "NR"; }

		DL_Group.Format group_format() const { return DL_Group.ANSI_X9_57; }

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return group_q().bytes(); }
		size_t max_input_bits() const { return (group_q().bits() - 1); }

		NR_PublicKey(in AlgorithmIdentifier alg_id,
						 in SafeVector!ubyte key_bits);

		NR_PublicKey(in DL_Group group, const ref BigInt pub_key);
	package:
		NR_PublicKey() {}
};

/**
* Nyberg-Rueppel Private Key
*/
class NR_PrivateKey : NR_PublicKey,
										  public abstract DL_Scheme_PrivateKey
{
	public:
		bool check_key(RandomNumberGenerator rng, bool strong) const;

		NR_PrivateKey(in AlgorithmIdentifier alg_id,
						  in SafeVector!ubyte key_bits,
						  RandomNumberGenerator rng);

		NR_PrivateKey(RandomNumberGenerator rng,
						  const ref DL_Group group,
						  const ref BigInt x = 0);
};

/**
* Nyberg-Rueppel signature operation
*/
class NR_Signature_Operation : pk_ops.Signature
{
	public:
		NR_Signature_Operation(in NR_PrivateKey nr);

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return q.bytes(); }
		size_t max_input_bits() const { return (q.bits() - 1); }

		SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
										RandomNumberGenerator rng);
	private:
		const ref BigInt q;
		const ref BigInt x;
		Fixed_Base_Power_Mod powermod_g_p;
		Modular_Reducer mod_q;
};

/**
* Nyberg-Rueppel verification operation
*/
class NR_Verification_Operation : pk_ops.Verification
{
	public:
		NR_Verification_Operation(in NR_PublicKey nr);

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return q.bytes(); }
		size_t max_input_bits() const { return (q.bits() - 1); }

		bool with_recovery() const { return true; }

		SafeVector!ubyte verify_mr(in ubyte* msg, size_t msg_len);
	private:
		const ref BigInt q;
		const ref BigInt y;

		Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
		Modular_Reducer mod_p, mod_q;
};