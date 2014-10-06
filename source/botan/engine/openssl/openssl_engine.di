/*
* OpenSSL Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.engine;
/**
* OpenSSL Engine
*/
class OpenSSL_Engine : Engine
{
	public:
		override string provider_name() const { return "openssl"; }

		PK_Ops::Key_Agreement*
			override get_key_agreement_op(in Private_Key key, RandomNumberGenerator rng) const;

		PK_Ops::Signature*
			override get_signature_op(in Private_Key key, RandomNumberGenerator rng) const;

		override PK_Ops::Verification* get_verify_op(in Public_Key key, RandomNumberGenerator rng) const;

		override PK_Ops::Encryption* get_encryption_op(in Public_Key key, RandomNumberGenerator rng) const;

		override PK_Ops::Decryption* get_decryption_op(in Private_Key key, RandomNumberGenerator rng) const;

		Modular_Exponentiator* mod_exp(in BigInt,
												 override Power_Mod::Usage_Hints) const;

		BlockCipher find_block_cipher(in SCAN_Name,
												 override ref Algorithm_Factory) const;

		StreamCipher find_stream_cipher(in SCAN_Name,
													override ref Algorithm_Factory) const;

		override HashFunction find_hash(in SCAN_Name, ref Algorithm_Factory) const;
};