/*
* Core Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.engine;
/**
* Core Engine
*/
class Core_Engine : Engine
{
	public:
		override string provider_name() const { return "core"; }

		PK_Ops::Key_Agreement*
			override get_key_agreement_op(in Private_Key key, RandomNumberGenerator rng) const;

		PK_Ops::Signature*
			override get_signature_op(in Private_Key key, RandomNumberGenerator rng) const;

		override PK_Ops::Verification* get_verify_op(in Public_Key key, RandomNumberGenerator rng) const;

		override PK_Ops::Encryption* get_encryption_op(in Public_Key key, RandomNumberGenerator rng) const;

		override PK_Ops::Decryption* get_decryption_op(in Private_Key key, RandomNumberGenerator rng) const;

		Modular_Exponentiator* mod_exp(in BigInt n,
												 override Power_Mod::Usage_Hints) const;

		Keyed_Filter* get_cipher(in string, Cipher_Dir,
										 ref Algorithm_Factory);

		BlockCipher find_block_cipher(in SCAN_Name,
												 override ref Algorithm_Factory) const;

		StreamCipher find_stream_cipher(in SCAN_Name,
													override ref Algorithm_Factory) const;

		HashFunction find_hash(in SCAN_Name request,
										override ref Algorithm_Factory) const;

		MessageAuthenticationCode find_mac(in SCAN_Name request,
														override ref Algorithm_Factory) const;

		PBKDF find_pbkdf(in SCAN_Name algo_spec,
								override ref Algorithm_Factory af) const;
};

/**
* Create a cipher mode filter object
* @param block_cipher a block cipher object
* @param direction are we encrypting or decrypting?
* @param mode the name of the cipher mode to use
* @param padding the mode padding to use (only used for ECB, CBC)
*/
Keyed_Filter* get_cipher_mode(const BlockCipher block_cipher,
										Cipher_Dir direction,
										in string mode,
										in string padding);