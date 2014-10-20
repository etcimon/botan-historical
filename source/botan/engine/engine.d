/*
* Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.engine;

import botan.engine.engine;
import botan.algo_base.scan_name;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.hash.hash;
import botan.mac.mac;
import botan.pbkdf.pbkdf;
import botan.math.numbertheory.pow_mod;
import botan.pubkey.pk_keys;
import botan.pubkey.pk_ops;
import botan.algo_factory.algo_factory : AlgorithmFactory;

class Keyed_Filter;
class RandomNumberGenerator;

/**
* Base class for all engines. All non-pure abstract functions simply
* return NULL, indicating the algorithm in question is not
* supported. Subclasses can reimplement whichever function(s)
* they want to hook in a particular type.
*/
interface Engine
{
public:
	/**
	* @return name of this engine
	*/
	string provider_name() const;

	/**
	* @param algo_spec the algorithm name/specification
	* @param af an algorithm factory object
	* @return newly allocated object, or NULL
	*/
	BlockCipher find_block_cipher(in SCAN_Name algo_spec,
	                              AlgorithmFactory af) const;


	/**
	* @param algo_spec the algorithm name/specification
	* @param af an algorithm factory object
	* @return newly allocated object, or NULL
	*/
	StreamCipher find_stream_cipher(in SCAN_Name algo_spec,
	                                AlgorithmFactory af) const;

	/**
	* @param algo_spec the algorithm name/specification
	* @param af an algorithm factory object
	* @return newly allocated object, or NULL
	*/
	HashFunction find_hash(in SCAN_Name algo_spec,
	                       AlgorithmFactory af) const;


	/**
	* @param algo_spec the algorithm name/specification
	* @param af an algorithm factory object
	* @return newly allocated object, or NULL
	*/
	MessageAuthenticationCode find_mac(in SCAN_Name algo_spec,
	                                   AlgorithmFactory af) const;

	/**
	* @param algo_spec the algorithm name/specification
	* @param af an algorithm factory object
	* @return newly allocated object, or NULL
	*/
	PBKDF find_pbkdf(in SCAN_Name algo_spec,
	                 AlgorithmFactory af) const;

	/**
	* @param n the modulus
	* @param hints any use hints
	* @return newly allocated object, or NULL
	*/
	Modular_Exponentiator mod_exp(in BigInt n,
	                              Power_Mod.Usage_Hints hints) const;

	/**
	* Return a new cipher object
	* @param algo_spec the algorithm name/specification
	* @param dir specifies if encryption or decryption is desired
	* @param af an algorithm factory object
	* @return newly allocated object, or NULL
	*/
	Keyed_Filter get_cipher(in string algo_spec,
	                        Cipher_Dir dir,
	                        AlgorithmFactory af);

	/**
	* Return a new operator object for this key, if possible
	* @param key the key we want an operator for
	* @return newly allocated operator object, or NULL
	*/
	Key_Agreement get_key_agreement_op(in Private_Key key, RandomNumberGenerator rng) const;

	/**
	* Return a new operator object for this key, if possible
	* @param key the key we want an operator for
	* @return newly allocated operator object, or NULL
	*/
	Signature get_signature_op(in Private_Key key, RandomNumberGenerator rng) const;

	/**
	* Return a new operator object for this key, if possible
	* @param key the key we want an operator for
	* @return newly allocated operator object, or NULL
	*/
	Verification get_verify_op(in Public_Key key, RandomNumberGenerator rng) const;

	/**
	* Return a new operator object for this key, if possible
	* @param key the key we want an operator for
	* @return newly allocated operator object, or NULL
	*/
	Encryption get_encryption_op(in Public_Key key, RandomNumberGenerator rng) const;

	/**
	* Return a new operator object for this key, if possible
	* @param key the key we want an operator for
	* @return newly allocated operator object, or NULL
	*/
	Decryption get_decryption_op(in Private_Key key, RandomNumberGenerator rng) const;
};
