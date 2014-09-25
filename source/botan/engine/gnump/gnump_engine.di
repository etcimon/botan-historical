/*
* GMP Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENGINE_GMP_H__
#define BOTAN_ENGINE_GMP_H__

#include <botan/engine.h>

namespace Botan {

/**
* Engine using GNU MP
*/
class GMP_Engine : public Engine
	{
	public:
		GMP_Engine();
		~GMP_Engine();

		string provider_name() const override { return "gmp"; }

		PK_Ops::Key_Agreement*
		get_key_agreement_op(const Private_Key& key, RandomNumberGenerator&) const override;

		PK_Ops::Signature*
		get_signature_op(const Private_Key& key, RandomNumberGenerator&) const override;

		PK_Ops::Verification* get_verify_op(const Public_Key& key, RandomNumberGenerator&) const override;

		PK_Ops::Encryption* get_encryption_op(const Public_Key& key, RandomNumberGenerator&) const override;

		PK_Ops::Decryption* get_decryption_op(const Private_Key& key, RandomNumberGenerator&) const override;

		Modular_Exponentiator* mod_exp(const BigInt&,
												 Power_Mod::Usage_Hints) const override;
	};

}

#endif
