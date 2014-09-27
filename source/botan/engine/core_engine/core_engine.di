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
class Core_Engine : public Engine
{
	public:
		string provider_name() const override { return "core"; }

		PK_Ops::Key_Agreement*
			get_key_agreement_op(in Private_Key key, RandomNumberGenerator& rng) const override;

		PK_Ops::Signature*
			get_signature_op(in Private_Key key, RandomNumberGenerator& rng) const override;

		PK_Ops::Verification* get_verify_op(in Public_Key key, RandomNumberGenerator& rng) const override;

		PK_Ops::Encryption* get_encryption_op(in Public_Key key, RandomNumberGenerator& rng) const override;

		PK_Ops::Decryption* get_decryption_op(in Private_Key key, RandomNumberGenerator& rng) const override;

		Modular_Exponentiator* mod_exp(in BigInt n,
												 Power_Mod::Usage_Hints) const override;

		Keyed_Filter* get_cipher(in string, Cipher_Dir,
										 Algorithm_Factory&);

		BlockCipher* find_block_cipher(in SCAN_Name,
												 Algorithm_Factory&) const override;

		StreamCipher* find_stream_cipher(in SCAN_Name,
													Algorithm_Factory&) const override;

		HashFunction* find_hash(in SCAN_Name request,
										Algorithm_Factory&) const override;

		MessageAuthenticationCode* find_mac(in SCAN_Name request,
														Algorithm_Factory&) const override;

		PBKDF* find_pbkdf(in SCAN_Name algo_spec,
								Algorithm_Factory& af) const override;
};

/**
* Create a cipher mode filter object
* @param block_cipher a block cipher object
* @param direction are we encrypting or decrypting?
* @param mode the name of the cipher mode to use
* @param padding the mode padding to use (only used for ECB, CBC)
*/
Keyed_Filter* get_cipher_mode(const BlockCipher* block_cipher,
										Cipher_Dir direction,
										in string mode,
										in string padding);