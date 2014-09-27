/*
* Public Key Interface
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/pk_keys.h>
#include <botan/pk_ops.h>
#include <botan/symkey.h>
#include <botan/rng.h>
#include <botan/eme.h>
#include <botan/emsa.h>
#include <botan/kdf.h>
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
		* @param in the message as a byte array
		* @param length the length of the above byte array
		* @param rng the random number source to use
		* @return encrypted message
		*/
		Vector!( byte ) encrypt(in byte* input, size_t length,
											RandomNumberGenerator& rng) const
		{
			return enc(input, length, rng);
		}

		/**
		* Encrypt a message.
		* @param in the message
		* @param rng the random number source to use
		* @return encrypted message
		*/
		Vector!( byte ) encrypt(Alloc)(in Vector!( byte, Alloc ) input,
										  RandomNumberGenerator& rng) const
		{
			return enc(&input[0], input.size(), rng);
		}

		/**
		* Return the maximum allowed message size in bytes.
		* @return maximum message size in bytes
		*/
		abstract size_t maximum_input_size() const;

		PK_Encryptor() {}
		abstract ~PK_Encryptor() {}

		PK_Encryptor(in PK_Encryptor);

		PK_Encryptor& operator=(in PK_Encryptor);

	private:
		abstract Vector!( byte ) enc(in byte*, size_t,
												 RandomNumberGenerator&) const;
};

/**
* Public Key Decryptor
*/
class PK_Decryptor
{
	public:
		/**
		* Decrypt a ciphertext.
		* @param in the ciphertext as a byte array
		* @param length the length of the above byte array
		* @return decrypted message
		*/
		SafeVector!byte decrypt(in byte* input, size_t length) const
		{
			return dec(input, length);
		}

		/**
		* Decrypt a ciphertext.
		* @param in the ciphertext
		* @return decrypted message
		*/
		SafeVector!byte decrypt(Alloc)(in Vector!( byte, Alloc ) input) const
		{
			return dec(&input[0], input.size());
		}

		PK_Decryptor() {}
		abstract ~PK_Decryptor() {}

		PK_Decryptor(in PK_Decryptor);
		PK_Decryptor& operator=(in PK_Decryptor);

	private:
		abstract SafeVector!byte dec(in byte*, size_t) const;
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
		* @param in the message to sign as a byte array
		* @param length the length of the above byte array
		* @param rng the rng to use
		* @return signature
		*/
		Vector!( byte ) sign_message(in byte* input, size_t length,
												  RandomNumberGenerator& rng);

		/**
		* Sign a message.
		* @param in the message to sign
		* @param rng the rng to use
		* @return signature
		*/
		Vector!( byte ) sign_message(in Vector!byte input,
												 RandomNumberGenerator& rng)
		{ return sign_message(&input[0], input.size(), rng); }

		Vector!( byte ) sign_message(in SafeVector!byte input,
												 RandomNumberGenerator& rng)
		{ return sign_message(&input[0], input.size(), rng); }

		/**
		* Add a message part (single byte).
		* @param in the byte to add
		*/
		void update(byte input) { update(&input, 1); }

		/**
		* Add a message part.
		* @param in the message part to add as a byte array
		* @param length the length of the above byte array
		*/
		void update(in byte* input, size_t length);

		/**
		* Add a message part.
		* @param in the message part to add
		*/
		void update(in Vector!byte input) { update(&input[0], input.size()); }

		/**
		* Get the signature of the so far processed message (provided by the
		* calls to update()).
		* @param rng the rng to use
		* @return signature of the total message
		*/
		Vector!( byte ) signature(RandomNumberGenerator& rng);

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
		bool self_test_signature(in Vector!byte msg,
										 in Vector!byte sig) const;

		std::unique_ptr<PK_Ops::Signature> m_op;
		std::unique_ptr<PK_Ops::Verification> m_verify_op;
		std::unique_ptr<EMSA> m_emsa;
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
		* @param msg the message that the signature belongs to, as a byte array
		* @param msg_length the length of the above byte array msg
		* @param sig the signature as a byte array
		* @param sig_length the length of the above byte array sig
		* @return true if the signature is valid
		*/
		bool verify_message(in byte* msg, size_t msg_length,
								  in byte* sig, size_t sig_length);
		/**
		* Verify a signature.
		* @param msg the message that the signature belongs to
		* @param sig the signature
		* @return true if the signature is valid
		*/
		bool verify_message(Alloc, Alloc2)(in Vector!( byte, Alloc ) msg,
								  const Vector!( byte, Alloc2 )& sig)
		{
			return verify_message(&msg[0], msg.size(),
										 &sig[0], sig.size());
		}

		/**
		* Add a message part (single byte) of the message corresponding to the
		* signature to be verified.
		* @param in the byte to add
		*/
		void update(byte input) { update(&in, 1); }

		/**
		* Add a message part of the message corresponding to the
		* signature to be verified.
		* @param msg_part the new message part as a byte array
		* @param length the length of the above byte array
		*/
		void update(in byte* msg_part, size_t length);

		/**
		* Add a message part of the message corresponding to the
		* signature to be verified.
		* @param in the new message part
		*/
		void update(in Vector!byte input)
		{ update(&input[0], in.size()); }

		/**
		* Check the signature of the buffered message, i.e. the one build
		* by successive calls to update.
		* @param sig the signature to be verified as a byte array
		* @param length the length of the above byte array
		* @return true if the signature is valid, false otherwise
		*/
		bool check_signature(in byte* sig, size_t length);

		/**
		* Check the signature of the buffered message, i.e. the one build
		* by successive calls to update.
		* @param sig the signature to be verified
		* @return true if the signature is valid, false otherwise
		*/
		bool check_signature(Alloc)(in Vector!( byte, Alloc ) sig)
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
		PK_Verifier(in Public_Key pub_key,
						in string emsa,
						Signature_Format format = IEEE_1363);
	private:
		bool validate_signature(in SafeVector!byte msg,
										in byte* sig, size_t sig_len);

		std::unique_ptr<PK_Ops::Verification> m_op;
		std::unique_ptr<EMSA> m_emsa;
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
		* @param in the other parties key
		* @param in_len the length of in in bytes
		* @param params extra derivation params
		* @param params_len the length of params in bytes
		*/
		SymmetricKey derive_key(size_t key_len,
										in byte* in,
										size_t in_len,
										in byte* params,
										size_t params_len) const;

		/*
		* Perform Key Agreement Operation
		* @param key_len the desired key output size
		* @param in the other parties key
		* @param in_len the length of in in bytes
		* @param params extra derivation params
		* @param params_len the length of params in bytes
		*/
		SymmetricKey derive_key(size_t key_len,
										in Vector!byte input,
										in byte* params,
										size_t params_len) const
		{
			return derive_key(key_len, &input[0], input.size(),
									params, params_len);
		}

		/*
		* Perform Key Agreement Operation
		* @param key_len the desired key output size
		* @param in the other parties key
		* @param in_len the length of in in bytes
		* @param params extra derivation params
		*/
		SymmetricKey derive_key(size_t key_len,
										in byte* input, size_t in_len,
										in string params = "") const
		{
			return derive_key(key_len, input, in_len,
									cast(const byte*)(params.data()),
									params.length());
		}

		/*
		* Perform Key Agreement Operation
		* @param key_len the desired key output size
		* @param in the other parties key
		* @param params extra derivation params
		*/
		SymmetricKey derive_key(size_t key_len,
										in Vector!byte input,
										in string params = "") const
		{
			return derive_key(key_len, &input[0], input.size(),
									cast(const byte*)(params.data()),
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
		std::unique_ptr<PK_Ops::Key_Agreement> m_op;
		std::unique_ptr<KDF> m_kdf;
};

/**
* Encryption with an MR algorithm and an EME.
*/
class PK_Encryptor_EME : public PK_Encryptor
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
		Vector!( byte ) enc(in byte*, size_t,
									  RandomNumberGenerator& rng) const;

		std::unique_ptr<PK_Ops::Encryption> m_op;
		std::unique_ptr<EME> m_eme;
};

/**
* Decryption with an MR algorithm and an EME.
*/
class PK_Decryptor_EME : public PK_Decryptor
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
		SafeVector!byte dec(const byte[], size_t) const;

		std::unique_ptr<PK_Ops::Decryption> m_op;
		std::unique_ptr<EME> m_eme;
};