/*
* Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ENGINE_H__
#define BOTAN_ENGINE_H__

#include <botan/scan_name.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
#include <botan/mac.h>
#include <botan/pbkdf.h>
#include <botan/pow_mod.h>
#include <botan/pk_keys.h>
#include <botan/pk_ops.h>

namespace Botan {

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
		abstract ~Engine() {}

		/**
		* @return name of this engine
		*/
		abstract string provider_name() const = 0;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract BlockCipher*
			find_block_cipher(const SCAN_Name& algo_spec,
									Algorithm_Factory& af) const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract StreamCipher*
			find_stream_cipher(const SCAN_Name& algo_spec,
									 Algorithm_Factory& af) const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract HashFunction*
			find_hash(const SCAN_Name& algo_spec,
						 Algorithm_Factory& af) const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract MessageAuthenticationCode*
			find_mac(const SCAN_Name& algo_spec,
						Algorithm_Factory& af) const;

		/**
		* @param algo_spec the algorithm name/specification
		* @param af an algorithm factory object
		* @return newly allocated object, or NULL
		*/
		abstract PBKDF* find_pbkdf(const SCAN_Name& algo_spec,
										  Algorithm_Factory& af) const;

		/**
		* @param n the modulus
		* @param hints any use hints
		* @return newly allocated object, or NULL
		*/
		abstract Modular_Exponentiator*
			mod_exp(const BigInt& n,
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
			get_key_agreement_op(const Private_Key& key, RandomNumberGenerator& rng) const;

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Signature*
			get_signature_op(const Private_Key& key, RandomNumberGenerator& rng) const;

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Verification*
			get_verify_op(const Public_Key& key, RandomNumberGenerator& rng) const;

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Encryption*
			get_encryption_op(const Public_Key& key, RandomNumberGenerator& rng) const;

		/**
		* Return a new operator object for this key, if possible
		* @param key the key we want an operator for
		* @return newly allocated operator object, or NULL
		*/
		abstract PK_Ops::Decryption*
			get_decryption_op(const Private_Key& key, RandomNumberGenerator& rng) const;
	};

}

#endif
