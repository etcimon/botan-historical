/*
* Public Key Interface
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pubkey;

import botan.utils.types;
public import botan.pubkey.pk_keys;
public import botan.pubkey.pk_ops;
public import botan.algo_base.symkey;
import botan.rng.rng;
import botan.pk_pad.eme;
import botan.pk_pad.emsa;
import botan.kdf.kdf;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.bigint.bigint;
import botan.utils.parsing;
import botan.libstate.libstate;
import botan.engine.engine;
import botan.utils.bit_ops;

typedef bool Signature_Format;
/**
* The two types of signature format supported by Botan.
*/
enum : Signature_Format { IEEE_1363, DER_SEQUENCE }
typedef bool Fault_Protection;
/**
* Enum marking if protection against fault attacks should be used
*/
enum : Fault_Protection {
	ENABLE_FAULT_PROTECTION,
	DISABLE_FAULT_PROTECTION
}

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
		return enc(&input[0], input.length, rng);
	}

	/**
	* Return the maximum allowed message size in bytes.
	* @return maximum message size in bytes
	*/
	abstract size_t maximum_input_size() const;

	this() {}
	~this() {}

private:
	abstract Vector!ubyte enc(in ubyte*, size_t,
											 RandomNumberGenerator) const;
}

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
	Secure_Vector!ubyte decrypt(in ubyte* input, size_t length) const
	{
		return dec(input, length);
	}

	/**
	* Decrypt a ciphertext.
	* @param input the ciphertext
	* @return decrypted message
	*/
	Secure_Vector!ubyte decrypt(Alloc)(in Vector!( ubyte, Alloc ) input) const
	{
		return dec(&input[0], input.length);
	}

	this() {}
	~this() {}

private:
	abstract Secure_Vector!ubyte dec(in ubyte*, size_t) const;
}

/**
* Public Key Signer. Use the sign_message() functions for small
* messages. Use multiple calls update() to process large messages and
* generate the signature by finally calling signature().
*/
struct PK_Signer
{
public:
	/**
	* Sign a message.
	* @param input the message to sign as a ubyte array
	* @param length the length of the above ubyte array
	* @param rng the rng to use
	* @return signature
	*/
	Vector!ubyte sign_message(in ubyte* msg, size_t length,
	                          RandomNumberGenerator rng)
	{
		update(msg, length);
		return signature(rng);
	}

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
	{ return sign_message(&input[0], input.length, rng); }

	Vector!ubyte sign_message(in Secure_Vector!ubyte input,
											 RandomNumberGenerator rng)
	{ return sign_message(&input[0], input.length, rng); }

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
	void update(in ubyte* input, size_t length)
	{
		m_emsa.update(input, length);
	}

	/**
	* Add a message part.
	* @param input the message part to add
	*/
	void update(in Vector!ubyte input) { update(&input[0], input.length); }

	/**
	* Get the signature of the so far processed message (provided by the
	* calls to update()).
	* @param rng the rng to use
	* @return signature of the total message
	*/
	Vector!ubyte signature(RandomNumberGenerator rng)
	{
		Vector!ubyte encoded = unlock(m_emsa.encoding_of(m_emsa.raw_data(),
		                                                 m_op.max_input_bits(),
		                                                 rng));
		
		Vector!ubyte plain_sig = unlock(m_op.sign(&encoded[0], encoded.length, rng));
		
		assert(self_test_signature(encoded, plain_sig), "Signature was consistent");
		
		if (m_op.message_parts() == 1 || m_sig_format == IEEE_1363)
			return plain_sig;
		
		if (m_sig_format == DER_SEQUENCE)
		{
			if (plain_sig.length % m_op.message_parts())
				throw new Encoding_Error("PK_Signer: strange signature size found");
			const size_t SIZE_OF_PART = plain_sig.length / m_op.message_parts();

			Vector!BigInt sig_parts = Vector!BigInt(m_op.message_parts());
			for (size_t j = 0; j != sig_parts.length; ++j)
				sig_parts[j].binary_decode(&plain_sig[SIZE_OF_PART*j], SIZE_OF_PART);
			
			return DER_Encoder()
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode_list(sig_parts)
					.end_cons()
					.get_contents_unlocked();
		}
		else
			throw new Encoding_Error("PK_Signer: Unknown signature format " ~
			                         std.conv.to!string(m_sig_format));
	}

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
	this(in Private_Key key,
	     in string emsa_name,
	     Signature_Format format = IEEE_1363,
	     Fault_Protection prot = ENABLE_FAULT_PROTECTION)
	{
		Algorithm_Factory af = global_state().algorithm_factory();

		RandomNumberGenerator rng = global_state().global_rng();
		
		m_op = null;
		m_verify_op = null;

		foreach (Engine engine; af.engines) {

			if (!m_op)
				m_op = engine.get_signature_op(key, rng);
			
			if (!m_verify_op && prot == ENABLE_FAULT_PROTECTION)
				m_verify_op = engine.get_verify_op(key, rng);
			
			if (m_op && (m_verify_op || prot == DISABLE_FAULT_PROTECTION))
				break;
		}
		
		if (!m_op || (!m_verify_op && prot == ENABLE_FAULT_PROTECTION))
			throw new Lookup_Error("Signing with " ~ key.algo_name ~ " not supported");
		
		m_emsa = get_emsa(emsa_name);
		m_sig_format = format;
	}
private:
	/*
	* Check the signature we just created, to help prevent fault attacks
	*/
	bool self_test_signature(in Vector!ubyte msg,
	                         in Vector!ubyte sig) const
	{
		if (!m_verify_op)
			return true; // checking disabled, assume ok
		
		if (m_verify_op.with_recovery())
		{
			Vector!ubyte recovered =
				unlock(m_verify_op.verify_mr(&sig[0], sig.length));
			
			if (msg.length > recovered.length)
			{
				size_t extra_0s = msg.length - recovered.length;
				
				for (size_t i = 0; i != extra_0s; ++i)
					if (msg[i] != 0)
						return false;
				
				return same_mem(&msg[extra_0s], &recovered[0], recovered.length);
			}
			
			return (recovered == msg);
		}
		else
			return m_verify_op.verify(&msg[0], msg.length,
			&sig[0], sig.length);
	}

	Unique!Signature m_op;
	Unique!Verification m_verify_op;
	Unique!EMSA m_emsa;
	Signature_Format m_sig_format;
}

/**
* Public Key Verifier. Use the verify_message() functions for small
* messages. Use multiple calls update() to process large messages and
* verify the signature by finally calling check_signature().
*/
struct PK_Verifier
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
	                    in ubyte* sig, size_t sig_length)
	{
		update(msg, msg_length);
		return check_signature(sig, sig_length);
	}

	/**
	* Verify a signature.
	* @param msg the message that the signature belongs to
	* @param sig the signature
	* @return true if the signature is valid
	*/
	bool verify_message(Alloc, Alloc2)(in Vector!( ubyte, Alloc ) msg,
							  const Vector!( ubyte, Alloc2 ) sig)
	{
		return verify_message(&msg[0], msg.length,
									 &sig[0], sig.length);
	}

	/**
	* Add a message part (single ubyte) of the message corresponding to the
	* signature to be verified.
	* @param input the ubyte to add
	*/
	void update(ubyte input) { update(&input, 1); }

	/**
	* Add a message part of the message corresponding to the
	* signature to be verified.
	* @param msg_part the new message part as a ubyte array
	* @param length the length of the above ubyte array
	*/
	void update(in ubyte* input, size_t length)
	{
		m_emsa.update(input, length);
	}

	/**
	* Add a message part of the message corresponding to the
	* signature to be verified.
	* @param input the new message part
	*/
	void update(in Vector!ubyte input)
	{ update(&input[0], input.length); }

	/**
	* Check the signature of the buffered message, i.e. the one build
	* by successive calls to update.
	* @param sig the signature to be verified as a ubyte array
	* @param length the length of the above ubyte array
	* @return true if the signature is valid, false otherwise
	*/
	bool check_signature(in ubyte* sig, size_t length)
	{
		try {
			if (m_sig_format == IEEE_1363)
				return validate_signature(m_emsa.raw_data(), sig, length);
			else if (m_sig_format == DER_SEQUENCE)
			{
				BER_Decoder decoder(sig, length);
				BER_Decoder ber_sig = decoder.start_cons(ASN1_Tag.SEQUENCE);
				
				size_t count = 0;
				Vector!ubyte real_sig;
				while(ber_sig.more_items())
				{
					BigInt sig_part;
					ber_sig.decode(sig_part);
					real_sig += BigInt.encode_1363(sig_part, m_op.message_part_size());
					++count;
				}
				
				if (count != m_op.message_parts())
					throw new Decoding_Error("PK_Verifier: signature size invalid");
				
				return validate_signature(m_emsa.raw_data(),
				                          &real_sig[0], real_sig.length);
			}
			else
				throw new Decoding_Error("PK_Verifier: Unknown signature format " ~
				                         std.conv.to!string(m_sig_format));
		}
		catch(Invalid_Argument) { return false; }
	}

	/**
	* Check the signature of the buffered message, i.e. the one build
	* by successive calls to update.
	* @param sig the signature to be verified
	* @return true if the signature is valid, false otherwise
	*/
	bool check_signature(Alloc)(in Vector!( ubyte, Alloc ) sig)
	{
		return check_signature(&sig[0], sig.length);
	}

	/**
	* Set the format of the signatures fed to this verifier.
	* @param format the signature format to use
	*/
	void set_input_format(Signature_Format format)
	{
		if (m_op.message_parts() == 1 && format != IEEE_1363)
			throw new Invalid_State("PK_Verifier: This algorithm always uses IEEE 1363");
		m_sig_format = format;
	}

	/**
	* Construct a PK Verifier.
	* @param pub_key the public key to verify against
	* @param emsa the EMSA to use (eg "EMSA3(SHA-1)")
	* @param format the signature format to use
	*/
	this(in Public_Key key,
	     in string emsa_name,
	     Signature_Format format = IEEE_1363)
	{
		Algorithm_Factory af = global_state().algorithm_factory();

		RandomNumberGenerator rng = global_state().global_rng();

		foreach (Engine engine; af.engines) {
			m_op = engine.get_verify_op(key, rng);
			if (m_op)
				break;
		}
		
		if (!m_op)
			throw new Lookup_Error("Verification with " ~ key.algo_name ~ " not supported");
		
		m_emsa = get_emsa(emsa_name);
		m_sig_format = format;
	}

private:
	bool validate_signature(in Secure_Vector!ubyte msg,
	                        in ubyte* sig, size_t sig_len)
	{
		if (m_op.with_recovery())
		{
			Secure_Vector!ubyte output_of_key = m_op.verify_mr(sig, sig_len);
			return m_emsa.verify(output_of_key, msg, m_op.max_input_bits());
		}
		else
		{
			RandomNumberGenerator rng = global_state().global_rng();
			
			Secure_Vector!ubyte encoded =
				m_emsa.encoding_of(msg, m_op.max_input_bits(), rng);
			
			return m_op.verify(&encoded[0], encoded.length, sig, sig_len);
		}
	}

	Unique!Verification m_op;
	Unique!EMSA m_emsa;
	Signature_Format m_sig_format;
}

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
	SymmetricKey derive_key(size_t key_len, in ubyte* input,
	                        size_t in_len, in ubyte* params,
	                        size_t params_len) const
	{
		Secure_Vector!ubyte z = m_op.agree(input, in_len);
		
		if (!m_kdf)
			return z;
		
		return m_kdf.derive_key(key_len, z, params, params_len);
	}

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
		return derive_key(key_len, &input[0], input.length,
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
								cast(const ubyte*)(params.ptr),
								params.length);
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
		return derive_key(key_len, &input[0], input.length,
								cast(const ubyte*)(params.ptr),
								params.length);
	}

	/**
	* Construct a PK Key Agreement.
	* @param key the key to use
	* @param kdf_name name of the KDF to use (or 'Raw' for no KDF)
	*/
	this(in PK_Key_Agreement_Key key,  in string kdf_name)
	{
		Algorithm_Factory af = global_state().algorithm_factory();
		RandomNumberGenerator rng = global_state().global_rng();

		foreach (Engine engine; af.engines)
		{
			m_op = engine.get_key_agreement_op(key, rng);
			if (m_op)
				break;
		}
		
		if (!m_op)
			throw new Lookup_Error("Key agreement with " ~ key.algo_name ~ " not supported");
		
		m_kdf = get_kdf(kdf_name);
	}
private:
	Unique!Key_Agreement m_op;
	Unique!KDF m_kdf;
}

/**
* Encryption with an MR algorithm and an EME.
*/
class PK_Encryptor_EME : PK_Encryptor
{
public:
	/*
	* Return the max size, in bytes, of a message
	*/
	size_t maximum_input_size() const
	{
		if (!m_eme)
			return (m_op.max_input_bits() / 8);
		else
			return m_eme.maximum_input_size(m_op.max_input_bits());
	}

	/**
	* Construct an instance.
	* @param key the key to use inside the decryptor
	* @param eme the EME to use
	*/
	this(in Public_Key key,
	     in string eme_name)
	{
		
		Algorithm_Factory af = global_state().algorithm_factory();
		RandomNumberGenerator rng = global_state().global_rng();

		foreach (Engine engine; af.engines) {
			m_op = engine.get_encryption_op(key, rng);
			if (m_op)
				break;
		}
		
		if (!m_op)
			throw new Lookup_Error("Encryption with " ~ key.algo_name ~ " not supported");
		
		m_eme = get_eme(eme_name);
	}

private:
	Vector!ubyte
		enc(in ubyte* input,
		    size_t length,
		    RandomNumberGenerator rng) const
	{
		if (m_eme)
		{
			Secure_Vector!ubyte encoded =
				m_eme.encode(input, length, m_op.max_input_bits(), rng);
			
			if (8*(encoded.length - 1) + high_bit(encoded[0]) > m_op.max_input_bits())
				throw new Invalid_Argument("PK_Encryptor_EME: Input is too large");
			
			return unlock(m_op.encrypt(&encoded[0], encoded.length, rng));
		}
		else
		{
			if (8*(length - 1) + high_bit(input[0]) > m_op.max_input_bits())
				throw new Invalid_Argument("PK_Encryptor_EME: Input is too large");
			
			return unlock(m_op.encrypt(&input[0], length, rng));
		}
	}

	Unique!Encryption m_op;
	Unique!EME m_eme;
}

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
	this(in Private_Key key,
		     in string eme_name)
	{
		Algorithm_Factory af = global_state().algorithm_factory();
		RandomNumberGenerator rng = global_state().global_rng();

		foreach (Engine engine; af.engines)
		{
			m_op = engine.get_decryption_op(key, rng);
			if (m_op)
				break;
		}
		
		if (!m_op)
			throw new Lookup_Error("Decryption with " ~ key.algo_name ~ " not supported");
		
		m_eme = get_eme(eme_name);
	}

private:
	/*
	* Decrypt a message
	*/
	Secure_Vector!ubyte dec(in ubyte* msg,
	                     size_t length) const
	{
		try {
			Secure_Vector!ubyte decrypted = m_op.decrypt(msg, length);
			if (m_eme)
				return m_eme.decode(decrypted, m_op.max_input_bits());
			else
				return decrypted;
		}
		catch(Invalid_Argument)
		{
			throw new Decoding_Error("PK_Decryptor_EME: Input is invalid");
		}
	}

	Unique!Decryption m_op;
	Unique!EME m_eme;
}