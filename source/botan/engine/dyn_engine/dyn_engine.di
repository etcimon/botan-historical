/**
* Dynamically Loaded Engine
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.engine.engine;
/**
* Dynamically_Loaded_Engine just proxies the requests to the underlying
* Engine object, and handles load/unload details
*/
class Dynamically_Loaded_Engine : Engine
{
public:
	/**
	* @param lib_path full pathname to DLL to load
	*/
	Dynamically_Loaded_Engine(in string lib_path);

	Dynamically_Loaded_Engine(in Dynamically_Loaded_Engine);

	Dynamically_Loaded_Engine& operator=(in Dynamically_Loaded_Engine);

	~this();

	override string provider_name() const { return engine.provider_name(); }

	override BlockCipher find_block_cipher(in SCAN_Name algo_spec,
											  Algorithm_Factory af) const
	{
		return engine.find_block_cipher(algo_spec, af);
	}

	override StreamCipher find_stream_cipher(in SCAN_Name algo_spec,
												 Algorithm_Factory af) const
	{
		return engine.find_stream_cipher(algo_spec, af);
	}

	override HashFunction find_hash(in SCAN_Name algo_spec,
									 Algorithm_Factory af) const
	{
		return engine.find_hash(algo_spec, af);
	}

	override MessageAuthenticationCode find_mac(in SCAN_Name algo_spec,
													 Algorithm_Factory af) const
	{
		return engine.find_mac(algo_spec, af);
	}

	override PBKDF find_pbkdf(in SCAN_Name algo_spec,
							 Algorithm_Factory af) const
	{
		return engine.find_pbkdf(algo_spec, af);
	}

	override Modular_Exponentiator mod_exp(in BigInt n,
											  power_mod.Usage_Hints hints) const
	{
		return engine.mod_exp(n, hints);
	}

	override Keyed_Filter get_cipher(in string algo_spec,
									 Cipher_Dir dir,
									 Algorithm_Factory af)
	{
		return engine.get_cipher(algo_spec, dir, af);
	}

	override pk_ops.Key_Agreement
		 get_key_agreement_op(in Private_Key key, RandomNumberGenerator rng) const
	{
		return engine.get_key_agreement_op(key, rng);
	}

	override pk_ops.Signature
		 get_signature_op(in Private_Key key, RandomNumberGenerator rng) const
	{
		return engine.get_signature_op(key, rng);
	}

	override pk_ops.Verification
		 get_verify_op(in Public_Key key, RandomNumberGenerator rng) const
	{
		return engine.get_verify_op(key, rng);
	}

	override pk_ops.Encryption
			get_encryption_op(in Public_Key key, RandomNumberGenerator rng) const
	{
		return engine.get_encryption_op(key, rng);
	}

	override pk_ops.Decryption
		 get_decryption_op(in Private_Key key, RandomNumberGenerator rng) const
	{
		return engine.get_decryption_op(key, rng);
	}

private:
	Dynamically_Loaded_Library lib;
	Engine engine;
};