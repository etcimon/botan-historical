/*
* Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.scan_name;
import botan.block_cipher;
import botan.stream_cipher;
import botan.hash;
import botan.mac;
import botan.pbkdf;
import botan.pow_mod;
import botan.pk_keys;
import botan.pk_ops;
class Algorithm_Factory;
class Keyed_Filter;
class RandomNumberGenerator;

/**
* Base class for all engines. All non-pure abstract functions simply
* return NULL, indicating the algorithm in question is not
* supported. Subclasses can reimplement whichever function(s)
* they want to hook in a particular type.
*/
class Engine
{
	public:
		~this() {}

		/**
		* @return name of this engine
		*/
		abstract string provider_name() const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract BlockCipher*
			find_block_cipher(in SCAN_Name algo_spec,
									Algorithm_Factory& af) const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract StreamCipher*
			find_stream_cipher(in SCAN_Name algo_spec,
									 Algorithm_Factory& af) const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract HashFunction*
			find_hash(in SCAN_Name algo_spec,
						 Algorithm_Factory& af) const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract MessageAuthenticationCode*
			find_mac(in SCAN_Name algo_spec,
						Algorithm_Factory& af) const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract PBKDF* find_pbkdf(in SCAN_Name algo_spec,
										  Algorithm_Factory& af) const;

		/**
		* @param n the modulus
		* @param hints any use hints
		* @return newly allocated object, or NULL
		*/
		abstract Modular_Exponentiator*
			mod_exp(in BigInt n,
					  Power_Mod::Usage_Hints hints) const;

		/**
		* Return a new cipher object
		* @param algo_spec the algorithm name/specification
		* @param dir specifies if encryption or decryption is desired
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract Keyed_Filter* get_cipher(in string algo_spec,
													Cipher_Dir dir,
													Algorithm_Factory& af);

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Key_Agreement*
			get_key_agreement_op(in Private_Key key, RandomNumberGenerator& rng) const;

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Signature*
			get_signature_op(in Private_Key key, RandomNumberGenerator& rng) const;

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Verification*
			get_verify_op(in Public_Key key, RandomNumberGenerator& rng) const;

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Encryption*
			get_encryption_op(in Public_Key key, RandomNumberGenerator& rng) const;

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Decryption*
			get_decryption_op(in Private_Key key, RandomNumberGenerator& rng) const;
};