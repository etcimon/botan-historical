/*
* GMP Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.engine;
/**
* Engine using GNU MP
*/
class GMP_Engine : public Engine
{
	public:
		GMP_Engine();
		~this();

		string provider_name() const override { return "gmp"; }

		PK_Ops::Key_Agreement*
		get_key_agreement_op(in Private_Key key, RandomNumberGenerator&) const override;

		PK_Ops::Signature*
		get_signature_op(in Private_Key key, RandomNumberGenerator&) const override;

		PK_Ops::Verification* get_verify_op(in Public_Key key, RandomNumberGenerator&) const override;

		PK_Ops::Encryption* get_encryption_op(in Public_Key key, RandomNumberGenerator&) const override;

		PK_Ops::Decryption* get_decryption_op(in Private_Key key, RandomNumberGenerator&) const override;

		Modular_Exponentiator* mod_exp(in BigInt,
												 Power_Mod::Usage_Hints) const override;
};