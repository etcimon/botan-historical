/*
* Nyberg-Rueppel
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/dl_algo.h>
#include <botan/pk_ops.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
/**
* Nyberg-Rueppel Public Key
*/
class NR_PublicKey : public abstract DL_Scheme_PublicKey
{
	public:
		string algo_name() const { return "NR"; }

		DL_Group::Format group_format() const { return DL_Group::ANSI_X9_57; }

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return group_q().bytes(); }
		size_t max_input_bits() const { return (group_q().bits() - 1); }

		NR_PublicKey(in AlgorithmIdentifier alg_id,
						 in SafeVector!byte key_bits);

		NR_PublicKey(in DL_Group group, ref const BigInt pub_key);
	protected:
		NR_PublicKey() {}
};

/**
* Nyberg-Rueppel Private Key
*/
class NR_PrivateKey : public NR_PublicKey,
										  public abstract DL_Scheme_PrivateKey
{
	public:
		bool check_key(RandomNumberGenerator& rng, bool strong) const;

		NR_PrivateKey(in AlgorithmIdentifier alg_id,
						  in SafeVector!byte key_bits,
						  RandomNumberGenerator& rng);

		NR_PrivateKey(RandomNumberGenerator& rng,
						  const DL_Group& group,
						  ref const BigInt x = 0);
};

/**
* Nyberg-Rueppel signature operation
*/
class NR_Signature_Operation : public PK_Ops::Signature
{
	public:
		NR_Signature_Operation(in NR_PrivateKey nr);

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return q.bytes(); }
		size_t max_input_bits() const { return (q.bits() - 1); }

		SafeVector!byte sign(in byte* msg, size_t msg_len,
										RandomNumberGenerator& rng);
	private:
		ref const BigInt q;
		ref const BigInt x;
		Fixed_Base_Power_Mod powermod_g_p;
		Modular_Reducer mod_q;
};

/**
* Nyberg-Rueppel verification operation
*/
class NR_Verification_Operation : public PK_Ops::Verification
{
	public:
		NR_Verification_Operation(in NR_PublicKey nr);

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return q.bytes(); }
		size_t max_input_bits() const { return (q.bits() - 1); }

		bool with_recovery() const { return true; }

		SafeVector!byte verify_mr(in byte* msg, size_t msg_len);
	private:
		ref const BigInt q;
		ref const BigInt y;

		Fixed_Base_Power_Mod powermod_g_p, powermod_y_p;
		Modular_Reducer mod_p, mod_q;
};