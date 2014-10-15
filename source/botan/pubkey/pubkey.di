/*
* Public Key Interface
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pk_keys;
import botan.pubkey.pk_ops;
import botan.algo_base.symkey;
import botan.rng;
import botan.eme;
import botan.emsa;
import botan.kdf;
/**
* The two types of signature format supported by Botan.
*/
enum Signature_Format { IEEE_1363, DER_SEQUENCE };

/**
* Enum marking if protection against fault attacks should be used
*/
enum Fault_Protection {
	ENABLE_FAULT_PROTECTION,
	DISABLE_FAULT_PROTECTION
};

/**
* Public Key Encryptor
*/
class PK_Encryptor
{
	public:

		/**
		* Encrypt a message.
		* @param input the message as a ubyte array
		* @param length the length of the above ubyte array
		* @param rng the random number source to use
		* @return encrypted message
		*/
		Vector!ubyte encrypt(in ubyte* input, size_t length,
											RandomNumberGenerator rng) const
		{
			return enc(input, length, rng);
		}

		/**
		* Encrypt a message.
		* @param input the message
		* @param rng the random number source to use
		* @return encrypted message
		*/
		Vector!ubyte encrypt(Alloc)(in Vector!( ubyte, Alloc ) input,
										  RandomNumberGenerator rng) const
		{
			return enc(&input[0], input.size(), rng);
		}

		/**
		* Return the maximum allowed message size in bytes.
		* @return maximum message size in bytes
		*/
		abstract size_t maximum_input_size() const;

		PK_Encryptor() {}
		~this() {}

		PK_Encryptor(in PK_Encryptor);

		PK_Encryptor& operator=(in PK_Encryptor);

	private:
		abstract Vector!ubyte enc(in ubyte*, size_t,
												 RandomNumberGenerator) const;
};

/**
* Public Key Decryptor
*/
class PK_Decryptor
{
	public:
		/**
		* Decrypt a ciphertext.
		* @param input the ciphertext as a ubyte array
		* @param length the length of the above ubyte array
		* @return decrypted message
		*/
		SafeVector!ubyte decrypt(in ubyte* input, size_t length) const
		{
			return dec(input, length);
		}

		/**
		* Decrypt a ciphertext.
		* @param input the ciphertext
		* @return decrypted message
		*/
		SafeVector!ubyte decrypt(Alloc)(in Vector!( ubyte, Alloc ) input) const
		{
			return dec(&input[0], input.size());
		}

		PK_Decryptor() {}
		~this() {}

		PK_Decryptor(in PK_Decryptor);
		PK_Decryptor& operator=(in PK_Decryptor);

	private:
		abstract SafeVector!ubyte dec(in ubyte*, size_t) const;
};

/**
* Public Key Signer. Use the sign_message() functions for small
* messages. Use multiple calls update() to process large messages and
* generate the signature by finally calling signature().
*/
class PK_Signer
{
	public:
		/**
		* Sign a message.
		* @param input the message to sign as a ubyte array
		* @param length the length of the above ubyte array
		* @param rng the rng to use
		* @return signature
		*/
		Vector!ubyte sign_message(in ubyte* input, size_t length,
												  RandomNumberGenerator rng);

		/**
		* Sign a message.
		* @param input the message to sign
		* @param rng the rng to use
		* @return signature
		*/
		Vector!ubyte sign_message(in Vector!ubyte input,
												 RandomNumberGenerator rng)
		{ return sign_message(&input[0], input.size(), rng); }

		Vector!ubyte sign_message(in SafeVector!ubyte input,
												 RandomNumberGenerator rng)
		{ return sign_message(&input[0], input.size(), rng); }

		/**
		* Add a message part (single ubyte).
		* @param input the ubyte to add
		*/
		void update(ubyte input) { update(&input, 1); }

		/**
		* Add a message part.
		* @param input the message part to add as a ubyte array
		* @param length the length of the above ubyte array
		*/
		void update(in ubyte* input, size_t length);

		/**
		* Add a message part.
		* @param input the message part to add
		*/
		void update(in Vector!ubyte input) { update(&input[0], input.size()); }

		/**
		* Get the signature of the so far processed message (provided by the
		* calls to update()).
		* @param rng the rng to use
		* @return signature of the total message
		*/
		Vector!ubyte signature(RandomNumberGenerator rng);

		/**
		* Set the output format of the signature.
		* @param format the signature format to use
		*/
		void set_output_format(Signature_Format format) { m_sig_format = format; }

		/**
		* Construct a PK Signer.
		* @param key the key to use inside this signer
		* @param emsa the EMSA to use
		* An example would be "EMSA1(SHA-224)".
		* @param format the signature format to use
		* @param prot says if fault protection should be enabled
		*/
		PK_Signer(in Private_Key key,
					 in string emsa,
					 Signature_Format format = IEEE_1363,
					 Fault_Protection prot = ENABLE_FAULT_PROTECTION);
	private:
		bool self_test_signature(in Vector!ubyte msg,
										 in Vector!ubyte sig) const;

		Unique!pk_ops.Signature m_op;
		Unique!pk_ops.Verification m_verify_op;
		Unique!EMSA m_emsa;
		Signature_Format m_sig_format;
};

/**
* Public Key Verifier. Use the verify_message() functions for small
* messages. Use multiple calls update() to process large messages and
* verify the signature by finally calling check_signature().
*/
class PK_Verifier
{
	public:
		/**
		* Verify a signature.
		* @param msg the message that the signature belongs to, as a ubyte array
		* @param msg_length the length of the above ubyte array msg
		* @param sig the signature as a ubyte array
		* @param sig_length the length of the above ubyte array sig
		* @return true if the signature is valid
		*/
		bool verify_message(in ubyte* msg, size_t msg_length,
								  in ubyte* sig, size_t sig_length);
		/**
		* Verify a signature.
		* @param msg the message that the signature belongs to
		* @param sig the signature
		* @return true if the signature is valid
		*/
		bool verify_message(Alloc, Alloc2)(in Vector!( ubyte, Alloc ) msg,
								  const Vector!( ubyte, Alloc2 ) sig)
		{
			return verify_message(&msg[0], msg.size(),
										 &sig[0], sig.size());
		}

		/**
		* Add a message part (single ubyte) of the message corresponding to the
		* signature to be verified.
		* @param input the ubyte to add
		*/
		void update(ubyte input) { update(&in, 1); }

		/**
		* Add a message part of the message corresponding to the
		* signature to be verified.
		* @param msg_part the new message part as a ubyte array
		* @param length the length of the above ubyte array
		*/
		void update(in ubyte* msg_part, size_t length);

		/**
		* Add a message part of the message corresponding to the
		* signature to be verified.
		* @param input the new message part
		*/
		void update(in Vector!ubyte input)
		{ update(&input[0], in.size()); }

		/**
		* Check the signature of the buffered message, i.e. the one build
		* by successive calls to update.
		* @param sig the signature to be verified as a ubyte array
		* @param length the length of the above ubyte array
		* @return true if the signature is valid, false otherwise
		*/
		bool check_signature(in ubyte* sig, size_t length);

		/**
		* Check the signature of the buffered message, i.e. the one build
		* by successive calls to update.
		* @param sig the signature to be verified
		* @return true if the signature is valid, false otherwise
		*/
		bool check_signature(Alloc)(in Vector!( ubyte, Alloc ) sig)
		{
			return check_signature(&sig[0], sig.size());
		}

		/**
		* Set the format of the signatures fed to this verifier.
		* @param format the signature format to use
		*/
		void set_input_format(Signature_Format format);

		/**
		* Construct a PK Verifier.
		* @param pub_key the public key to verify against
		* @param emsa the EMSA to use (eg "EMSA3(SHA-1)")
		* @param format the signature format to use
		*/
		this(in Public_Key pub_key,
						in string emsa,
						Signature_Format format = IEEE_1363);
	private:
		bool validate_signature(in SafeVector!ubyte msg,
										in ubyte* sig, size_t sig_len);

		Unique!pk_ops.Verification m_op;
		Unique!EMSA m_emsa;
		Signature_Format m_sig_format;
};

/**
* Key used for key agreement
*/
class PK_Key_Agreement
{
	public:

		/*
		* Perform Key Agreement Operation
		* @param key_len the desired key output size
		* @param input the other parties key
		* @param in_len the length of in in bytes
		* @param params extra derivation params
		* @param params_len the length of params in bytes
		*/
		SymmetricKey derive_key(size_t key_len,
										in ubyte* in,
										size_t in_len,
										in ubyte* params,
										size_t params_len) const;

		/*
		* Perform Key Agreement Operation
		* @param key_len the desired key output size
		* @param input the other parties key
		* @param in_len the length of in in bytes
		* @param params extra derivation params
		* @param params_len the length of params in bytes
		*/
		SymmetricKey derive_key(size_t key_len,
										in Vector!ubyte input,
										in ubyte* params,
										size_t params_len) const
		{
			return derive_key(key_len, &input[0], input.size(),
									params, params_len);
		}

		/*
		* Perform Key Agreement Operation
		* @param key_len the desired key output size
		* @param input the other parties key
		* @param in_len the length of in in bytes
		* @param params extra derivation params
		*/
		SymmetricKey derive_key(size_t key_len,
										in ubyte* input, size_t in_len,
										in string params = "") const
		{
			return derive_key(key_len, input, in_len,
									cast(const ubyte*)(params.data()),
									params.length());
		}

		/*
		* Perform Key Agreement Operation
		* @param key_len the desired key output size
		* @param input the other parties key
		* @param params extra derivation params
		*/
		SymmetricKey derive_key(size_t key_len,
										in Vector!ubyte input,
										in string params = "") const
		{
			return derive_key(key_len, &input[0], input.size(),
									cast(const ubyte*)(params.data()),
									params.length());
		}

		/**
		* Construct a PK Key Agreement.
		* @param key the key to use
		* @param kdf name of the KDF to use (or 'Raw' for no KDF)
		*/
		PK_Key_Agreement(in PK_Key_Agreement_Key key,
							  in string kdf);
	private:
		Unique!pk_ops.Key_Agreement m_op;
		Unique!KDF m_kdf;
};

/**
* Encryption with an MR algorithm and an EME.
*/
class PK_Encryptor_EME : PK_Encryptor
{
	public:
		size_t maximum_input_size() const;

		/**
		* Construct an instance.
		* @param key the key to use inside the decryptor
		* @param eme the EME to use
		*/
		PK_Encryptor_EME(in Public_Key key,
							  in string eme);
	private:
		Vector!ubyte enc(in ubyte*, size_t,
									  RandomNumberGenerator rng) const;

		Unique!pk_ops.Encryption m_op;
		Unique!EME m_eme;
};

/**
* Decryption with an MR algorithm and an EME.
*/
class PK_Decryptor_EME : PK_Decryptor
{
	public:
	  /**
		* Construct an instance.
		* @param key the key to use inside the encryptor
		* @param eme the EME to use
		*/
		PK_Decryptor_EME(in Private_Key key,
							  in string eme);
	private:
		SafeVector!ubyte dec(const ubyte[], size_t) const;

		Unique!pk_ops.Decryption m_op;
		Unique!EME m_eme;
};