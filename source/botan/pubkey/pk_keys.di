/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.alloc.secmem;
import botan.asn1.asn1_oid;
import botan.asn1.alg_id;
import botan.rng;
/**
* Public Key Base Class.
*/
class Public_Key
{
	public:
		/**
		* Get the name of the underlying public key scheme.
		* @return name of the public key scheme
		*/
		abstract string algo_name() const;

		/**
		* Return the estimated strength of the underlying key against
		* the best currently known attack. Note that this ignores anything
		* but pure attacks against the key itself and do not take into
		* account padding schemes, usage mistakes, etc which might reduce
		* the strength. However it does suffice to provide an upper bound.
		*
		* @return estimated strength in bits
		*/
		abstract size_t estimated_strength() const;

		/**
		* Get the OID of the underlying public key scheme.
		* @return OID of the public key scheme
		*/
		abstract OID get_oid() const;

		/**
		* Test the key values for consistency.
		* @param rng rng to use
		* @param strong whether to perform strong and lengthy version
		* of the test
		* @return true if the test is passed
		*/
		abstract bool check_key(RandomNumberGenerator rng,
									  bool strong) const;

		/**
		* Find out the number of message parts supported by this scheme.
		* @return number of message parts
		*/
		abstract size_t message_parts() const { return 1; }

		/**
		* Find out the message part size supported by this scheme/key.
		* @return size of the message parts in bits
		*/
		abstract size_t message_part_size() const { return 0; }

		/**
		* Get the maximum message size in bits supported by this public key.
		* @return maximum message size in bits
		*/
		abstract size_t max_input_bits() const;

		/**
		* @return X.509 AlgorithmIdentifier for this key
		*/
		abstract AlgorithmIdentifier algorithm_identifier() const;

		/**
		* @return X.509 subject key encoding for this key object
		*/
		abstract Vector!byte x509_subject_public_key() const;

		~this() {}
	package:
		/**
		* Self-test after loading a key
		* @param rng a random number generator
		*/
		abstract void load_check(RandomNumberGenerator rng) const;
};

/**
* Private Key Base Class
*/
class Private_Key : public abstract Public_Key
{
	public:
		/**
		* @return PKCS #8 private key encoding for this key object
		*/
		abstract SafeVector!byte pkcs8_Private_Key() const;

		/**
		* @return PKCS #8 AlgorithmIdentifier for this key
		* Might be different from the X.509 identifier, but normally is not
		*/
		abstract AlgorithmIdentifier pkcs8_algorithm_identifier() const
		{ return algorithm_identifier(); }

	package:
		/**
		* Self-test after loading a key
		* @param rng a random number generator
		*/
		void load_check(RandomNumberGenerator rng) const;

		/**
		* Self-test after generating a key
		* @param rng a random number generator
		*/
		void gen_check(RandomNumberGenerator rng) const;
};

/**
* PK Secret Value Derivation Key
*/
class PK_Key_Agreement_Key : public abstract Private_Key
{
	public:
		/*
		* @return public component of this key
		*/
		abstract Vector!byte public_value() const;

		~this() {}
};

/*
* Typedefs
*/
typedef PK_Key_Agreement_Key PK_KA_Key;
typedef Public_Key X509_PublicKey;
typedef Private_Key PKCS8_PrivateKey;