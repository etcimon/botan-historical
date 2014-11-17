/*
* PKCS #5 v2.0 PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbe.pbes2;

import botan.constants;
static if (BOTAN_HAS_PBE_PKCS_V20):

import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.asn1.oid_lookup.oids;
import botan.pbe.pbe;
import botan.block.block_cipher;
import botan.mac.mac;
import botan.filters.pipe;
import botan.pbkdf.pbkdf2;
import botan.algo_factory.algo_factory;
import botan.libstate.libstate;
import botan.libstate.lookup;
import botan.utils.parsing;
import botan.utils.types;
import std.datetime;
import std.algorithm;

/**
* PKCS #5 v2.0 PBE
*/
final class PBE_PKCS5v20 : PBE
{
public:
	/*
	* Return an OID for PBES2
	*/
	OID get_oid() const
	{
		return oids.lookup("PBE-PKCS5v20");
	}

	/*
	* Encode PKCS#5 PBES2 parameters
	*/
	Vector!ubyte encode_params() const
	{
		return DER_Encoder()
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(
					Algorithm_Identifier("PKCS5.PBKDF2",
				                    DER_Encoder()
				                    .start_cons(ASN1_Tag.SEQUENCE)
				                    .encode(salt, ASN1_Tag.OCTET_STRING)
				                    .encode(iterations)
				                    .encode(key_length)
				                    .encode_if (
					m_prf.name != "HMAC(SHA-160)",
					Algorithm_Identifier(m_prf.name,
				                    Algorithm_Identifier.USE_NULL_PARAM))
				                    .end_cons()
				                    .get_contents_unlocked()
				                    )
					)
				.encode(
					Algorithm_Identifier(block_cipher.name ~ "/CBC",
				                    DER_Encoder().encode(iv, ASN1_Tag.OCTET_STRING).get_contents_unlocked()
				                    )
					)
				.end_cons()
				.get_contents_unlocked();
	}

	@property string name() const
	{
		return "PBE-PKCS5v20(" ~ block_cipher.name ~ "," ~
			m_prf.name ~ ")";
	}

	/*
	* Encrypt some bytes using PBES2
	*/
	void write(in ubyte* input, size_t length)
	{
		pipe.write(input, length);
		flush_pipe(true);
	}

	/*
	* Start encrypting with PBES2
	*/
	void start_msg()
	{
		pipe.append(get_cipher(block_cipher.name ~ "/CBC/PKCS7",
		                       key, iv, direction));
		
		pipe.start_msg();
		if (pipe.message_count() > 1)
			pipe.set_default_msg(pipe.default_msg() + 1);
	}

	/*
	* Finish encrypting with PBES2
	*/
	void end_msg()
	{
		pipe.end_msg();
		flush_pipe(false);
		pipe.clear();
	}

	/**
	* Load a PKCS #5 v2.0 encrypted stream
	* @param params the PBES2 parameters
	* @param passphrase the passphrase to use for decryption
	*/
	this(in Vector!ubyte params,
	     in string passphrase) 
	{
		direction = DECRYPTION;
		block_cipher = null;
		m_prf = null;
		Algorithm_Identifier kdf_algo, enc_algo;
		
		BER_Decoder(params)
			.start_cons(ASN1_Tag.SEQUENCE)
				.decode(kdf_algo)
				.decode(enc_algo)
				.verify_end()
				.end_cons();
		
		Algorithm_Identifier prf_algo;
		
		if (kdf_algo.oid != oids.lookup("PKCS5.PBKDF2"))
			throw new Decoding_Error("PBE-PKCS5 v2.0: Unknown KDF algorithm " ~ kdf_algo.oid.toString());
		
		BER_Decoder(kdf_algo.parameters)
			.start_cons(ASN1_Tag.SEQUENCE)
				.decode(salt, ASN1_Tag.OCTET_STRING)
				.decode(iterations)
				.decode_optional(key_length, INTEGER, ASN1_Tag.UNIVERSAL)
				.decode_optional(prf_algo, ASN1_Tag.SEQUENCE, ASN1_Tag.CONSTRUCTED,
				                 Algorithm_Identifier("HMAC(SHA-160)",
				                    Algorithm_Identifier.USE_NULL_PARAM))
				.verify_end()
				.end_cons();
		
		Algorithm_Factory af = global_state().algorithm_factory();
		
		string cipher = oids.lookup(enc_algo.oid);
		Vector!string cipher_spec = splitter(cipher, '/');
		if (cipher_spec.length != 2)
			throw new Decoding_Error("PBE-PKCS5 v2.0: Invalid cipher spec " ~ cipher);
		
		if (cipher_spec[1] != "CBC")
			throw new Decoding_Error("PBE-PKCS5 v2.0: Don't know param format for " ~
			                         cipher);
		
		BER_Decoder(enc_algo.parameters).decode(iv, ASN1_Tag.OCTET_STRING).verify_end();
		
		block_cipher = af.make_block_cipher(cipher_spec[0]);
		m_prf = af.make_mac(oids.lookup(prf_algo.oid));
		
		if (key_length == 0)
			key_length = block_cipher.maximum_keylength();
		
		if (salt.length < 8)
			throw new Decoding_Error("PBE-PKCS5 v2.0: Encoded salt is too small");
		
		PKCS5_PBKDF2 pbkdf(m_prf.clone());
		
		key = pbkdf.derive_key(key_length, passphrase,
		                       salt.ptr, salt.length,
		iterations).bits_of();
	}

	/**
	* @param cipher the block cipher to use
	* @param mac the MAC to use
	* @param passphrase the passphrase to use for encryption
	* @param msec how many milliseconds to run the PBKDF
	* @param rng a random number generator
	*/
	this(BlockCipher cipher,
	     MessageAuthenticationCode mac,
	     in string passphrase,
	     Duration msec,
	     RandomNumberGenerator rng) 
	{
		direction = ENCRYPTION;
		block_cipher = cipher;
		m_prf = mac;
		salt = rng.random_vec(12);
		iv = rng.random_vec(block_cipher.block_size);
		iterations = 0;
		key_length = block_cipher.maximum_keylength();
		PKCS5_PBKDF2 pbkdf = PKCS5_PBKDF2(m_prf.clone());
		
		key = pbkdf.derive_key(key_length, passphrase,
		                     	salt.ptr, salt.length,
								msec, iterations).bits_of();
	}

	~this()
	{
		delete m_prf;
		delete block_cipher;
	}
private:
	/*
	* Flush the pipe
	*/
	void flush_pipe(bool safe_to_skip)
	{
		if (safe_to_skip && pipe.remaining() < 64)
			return;
		
		Secure_Vector!ubyte buffer = Secure_Vector!ubyte(DEFAULT_BUFFERSIZE);
		while (pipe.remaining())
		{
			const size_t got = pipe.read(buffer.ptr, buffer.length);
			send(buffer, got);
		}
	}

	Cipher_Dir direction;
	BlockCipher block_cipher;
	MessageAuthenticationCode m_prf;
	Secure_Vector!ubyte salt, key, iv;
	size_t iterations, key_length;
	Pipe pipe;
}