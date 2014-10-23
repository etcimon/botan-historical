/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pk_keys;

import botan.alloc.secmem;
import botan.asn1.asn1_oid;
import botan.asn1.alg_id;
import botan.rng.rng;
import botan.asn1.der_enc;
import botan.asn1.oid_lookup.oids;

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
	abstract @property string algo_name() const;

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
	final OID get_oid() const
	{
		try {
			return oids.lookup(algo_name);
		}
		catch(Lookup_Error)
		{
			throw new Lookup_Error("PK algo " ~ algo_name ~ " has no defined OIDs");
		}
	}


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
	* @return X.509 Algorithm_Identifier for this key
	*/
	abstract Algorithm_Identifier algorithm_identifier() const;

	/**
	* @return X.509 subject key encoding for this key object
	*/
	abstract Vector!ubyte x509_subject_public_key() const;

	~this() {}
protected:
	/**
	* Self-test after loading a key
	* @param rng a random number generator
	*/
	abstract void load_check(RandomNumberGenerator rng) const
	{
		if (!check_key(rng, BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD))
			throw new Invalid_Argument(algo_name ~ ": Invalid public key");
	}
};

/**
* Private Key Base Class
*/
class Private_Key : Public_Key
{
public:
	/**
	* @return PKCS #8 private key encoding for this key object
	*/
	abstract Secure_Vector!ubyte pkcs8_Private_Key() const;

	/**
	* @return PKCS #8 Algorithm_Identifier for this key
	* Might be different from the X.509 identifier, but normally is not
	*/
	abstract Algorithm_Identifier pkcs8_algorithm_identifier() const
	{ return algorithm_identifier(); }

protected:
	/**
	* Self-test after loading a key
	* @param rng a random number generator
	*/
	final override void load_check(RandomNumberGenerator rng) const
	{
		if (!check_key(rng, BOTAN_Private_Key_STRONG_CHECKS_ON_LOAD))
			throw new Invalid_Argument(algo_name ~ ": Invalid private key");
	}

	/**
	* Self-test after generating a key
	* @param rng a random number generator
	*/
	final void gen_check(RandomNumberGenerator rng) const
	{
		if (!check_key(rng, BOTAN_Private_Key_STRONG_CHECKS_ON_GENERATE))
			throw new Self_Test_Failure(algo_name ~ " private key generation failed");
	}
};

/**
* PK Secret Value Derivation Key
*/
class PK_Key_Agreement_Key : Private_Key
{
	public:
		/*
		* @return public component of this key
		*/
		abstract Vector!ubyte public_value() const;

		~this() {}
};

/*
* Typedefs
*/
typedef PK_Key_Agreement_Key PK_KA_Key;
typedef Public_Key X509_PublicKey;
typedef Private_Key PKCS8_PrivateKey;