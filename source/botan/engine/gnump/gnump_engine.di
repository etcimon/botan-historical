/*
* GMP Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.engine.engine;
/**
* Engine using GNU MP
*/
class GMP_Engine : Engine
{
public:
	GMP_Engine();
	~this();

	override string provider_name() const { return "gmp"; }

	override pk_ops.Key_Agreement
	 get_key_agreement_op(in Private_Key key, RandomNumberGenerator) const;

	override pk_ops.Signature
	 get_signature_op(in Private_Key key, RandomNumberGenerator) const;

	override pk_ops.Verification get_verify_op(in Public_Key key, RandomNumberGenerator) const;

	override pk_ops.Encryption get_encryption_op(in Public_Key key, RandomNumberGenerator) const;

	override pk_ops.Decryption get_decryption_op(in Private_Key key, RandomNumberGenerator) const;

	override Modular_Exponentiator mod_exp(in BigInt,
											Power_Mod::Usage_Hints) const;
};