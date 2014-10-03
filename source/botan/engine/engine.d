/*
* Engine
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.engine;
BlockCipher
Engine::find_block_cipher(in SCAN_Name,
								  ref Algorithm_Factory) const
{
	return null;
}

StreamCipher
Engine::find_stream_cipher(in SCAN_Name,
									ref Algorithm_Factory) const
{
	return null;
}

HashFunction
Engine::find_hash(in SCAN_Name,
						ref Algorithm_Factory) const
{
	return null;
}

MessageAuthenticationCode
Engine::find_mac(in SCAN_Name,
					  ref Algorithm_Factory) const
{
	return null;
}

PBKDF
Engine::find_pbkdf(in SCAN_Name,
						 ref Algorithm_Factory) const
{
	return null;
}

Modular_Exponentiator*
Engine::mod_exp(in BigInt,
					 Power_Mod::Usage_Hints) const
{
	return null;
}

Keyed_Filter* Engine::get_cipher(in string,
											Cipher_Dir,
											ref Algorithm_Factory)
{
	return null;
}

PK_Ops::Key_Agreement*
Engine::get_key_agreement_op(in Private_Key, RandomNumberGenerator) const
{
	return null;
}

PK_Ops::Signature*
Engine::get_signature_op(in Private_Key, RandomNumberGenerator) const
{
	return null;
}

PK_Ops::Verification*
Engine::get_verify_op(in Public_Key, RandomNumberGenerator) const
{
	return null;
}

PK_Ops::Encryption*
Engine::get_encryption_op(in Public_Key, RandomNumberGenerator) const
{
	return null;
}

PK_Ops::Decryption*
Engine::get_decryption_op(in Private_Key, RandomNumberGenerator) const
{
	return null;
}

}
