/*
* DSA
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.dl_algo;
import botan.pk_ops;
import botan.reducer;
import botan.pow_mod;
/**
* DSA Public Key
*/
class DSA_PublicKey : public abstract DL_Scheme_PublicKey
{
	public:
		string algo_name() const { return "DSA"; }

		DL_Group::Format group_format() const { return DL_Group::ANSI_X9_57; }
		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return group_q().bytes(); }
		size_t max_input_bits() const { return group_q().bits(); }

		DSA_PublicKey(in AlgorithmIdentifier alg_id,
						  in SafeVector!ubyte key_bits) :
			DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
		{
		}

		DSA_PublicKey(in DL_Group group, ref const BigInt y);
	package:
		DSA_PublicKey() {}
};

/**
* DSA Private Key
*/
class DSA_PrivateKey : public DSA_PublicKey,
											public abstract DL_Scheme_PrivateKey
{
	public:
		DSA_PrivateKey(in AlgorithmIdentifier alg_id,
							in SafeVector!ubyte key_bits,
							RandomNumberGenerator rng);

		DSA_PrivateKey(RandomNumberGenerator rng,
							const DL_Group& group,
							ref const BigInt Private_Key = 0);

		bool check_key(RandomNumberGenerator rng, bool strong) const;
};

/**
* Object that can create a DSA signature
*/
class DSA_Signature_Operation : public PK_Ops::Signature
{
	public:
		DSA_Signature_Operation(in DSA_PrivateKey dsa);

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return q.bytes(); }
		size_t max_input_bits() const { return q.bits(); }

		SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
										RandomNumberGenerator rng);
	private:
		ref const BigInt q;
		ref const BigInt x;
		Fixed_Base_Power_Mod powermod_g_p;
		Modular_Reducer mod_q;
};

/**
* Object that can verify a DSA signature
*/
class DSA_Verification_Operation : public PK_Ops::Verification
{
	public:
		DSA_Verification_Operation(in DSA_PublicKey dsa);

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return q.bytes(); }
		size_t max_input_bits() const { return q.bits(); }

		bool with_recovery() const { return false; }

		bool verify(in ubyte* msg, size_t msg_len,
						in ubyte* sig, size_t sig_len);
	private:
		ref const BigInt q;
		ref const BigInt y;

		Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
		Modular_Reducer mod_p, mod_q;
};