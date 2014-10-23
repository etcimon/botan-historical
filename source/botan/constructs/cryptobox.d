/*
* Cryptobox Message Routines
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.cryptobox;

import string;
import botan.rng.rng;
import botan.algo_base.symkey;
import botan.cryptobox;
import botan.filters.filters;
import botan.filters.pipe;
import botan.libstate.lookup;
import botan.hash.sha2_64;
import botan.mac.hmac;
import botan.pbkdf.pbkdf2;
import botan.codec.pem;
import botan.utils.get_byte;
import botan.utils.mem_ops;

/**
* This namespace holds various high-level crypto functions
*/
struct CryptoBox {

	/**
	* Encrypt a message using a passphrase
	* @param input the input data
	* @param input_len the length of input in bytes
	* @param passphrase the passphrase used to encrypt the message
	* @param rng a ref to a random number generator, such as AutoSeeded_RNG
	*/
	static string encrypt(in ubyte* input, size_t input_len,
	                      in string passphrase,
	                      RandomNumberGenerator rng)
	{
		Secure_Vector!ubyte pbkdf_salt = Secure_Vector!ubyte(PBKDF_SALT_LEN);
		rng.randomize(&pbkdf_salt[0], pbkdf_salt.length);
		
		PKCS5_PBKDF2 pbkdf = PKCS5_PBKDF2(new HMAC(new SHA_512));
		
		OctetString master_key = pbkdf.derive_key(
			PBKDF_OUTPUT_LEN,
			passphrase,
			&pbkdf_salt[0],
		pbkdf_salt.length,
		PBKDF_ITERATIONS);
		
		const ubyte* mk = master_key.begin();
		
		SymmetricKey cipher_key = SymmetricKey(&mk[0], CIPHER_KEY_LEN);
		SymmetricKey mac_key = SymmetricKey(&mk[CIPHER_KEY_LEN], MAC_KEY_LEN);
		InitializationVector iv = InitializationVector(&mk[CIPHER_KEY_LEN + MAC_KEY_LEN], CIPHER_IV_LEN);
		
		Pipe pipe = Pipe(get_cipher("Serpent/CTR-BE", cipher_key, iv, ENCRYPTION),
		          new Fork(null,
							new MAC_Filter(new HMAC(new SHA_512),
						               mac_key, MAC_OUTPUT_LEN)));
		
		pipe.process_msg(input, input_len);
		
		/*
		Output format is:
			version # (4 bytes)
			salt (10 bytes)
			mac (20 bytes)
			ciphertext
		*/
		const size_t ciphertext_len = pipe.remaining(0);
		
		Vector!ubyte out_buf = Vector!ubyte(VERSION_CODE_LEN +
		                     PBKDF_SALT_LEN +
		                     MAC_OUTPUT_LEN +
		                     ciphertext_len);
		
		for (size_t i = 0; i != VERSION_CODE_LEN; ++i)
			out_buf[i] = get_byte(i, CRYPTOBOX_VERSION_CODE);
		
		copy_mem(&out_buf[VERSION_CODE_LEN], &pbkdf_salt[0],  PBKDF_SALT_LEN);
		
		pipe.read(&out_buf[VERSION_CODE_LEN + PBKDF_SALT_LEN], MAC_OUTPUT_LEN, 1);
		pipe.read(&out_buf[VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN],
		ciphertext_len, 0);
		
		return pem.encode(out_buf, "BOTAN CRYPTOBOX MESSAGE");
	}

	/**
	* Decrypt a message encrypted with CryptoBox::encrypt
	* @param input the input data
	* @param input_len the length of input in bytes
	* @param passphrase the passphrase used to encrypt the message
	*/
	static string decrypt(in ubyte* input, size_t input_len,
	                      in string passphrase)
	{
		DataSource_Memory input_src(input, input_len);
		Secure_Vector!ubyte ciphertext =
			pem.decode_check_label(input_src,
			                       "BOTAN CRYPTOBOX MESSAGE");
		
		if (ciphertext.length < (VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN))
			throw new Decoding_Error("Invalid CryptoBox input");
		
		for (size_t i = 0; i != VERSION_CODE_LEN; ++i)
			if (ciphertext[i] != get_byte(i, CRYPTOBOX_VERSION_CODE))
				throw new Decoding_Error("Bad CryptoBox version");
		
		const ubyte* pbkdf_salt = &ciphertext[VERSION_CODE_LEN];
		
		PKCS5_PBKDF2 pbkdf = PKCS5_PBKDF2(new HMAC(new SHA_512));
		
		OctetString master_key = pbkdf.derive_key(
			PBKDF_OUTPUT_LEN,
			passphrase,
			pbkdf_salt,
			PBKDF_SALT_LEN,
			PBKDF_ITERATIONS);
		
		const ubyte* mk = master_key.begin();
		
		SymmetricKey cipher_key = SymmetricKey(&mk[0], CIPHER_KEY_LEN);
		SymmetricKey mac_key = SymmetricKey(&mk[CIPHER_KEY_LEN], MAC_KEY_LEN);
		InitializationVector iv = InitializationVector(&mk[CIPHER_KEY_LEN + MAC_KEY_LEN], CIPHER_IV_LEN);
		
		Pipe pipe = Pipe(new Fork(
							get_cipher("Serpent/CTR-BE", cipher_key, iv, DECRYPTION),
							new MAC_Filter(new HMAC(new SHA_512),
		              		mac_key, MAC_OUTPUT_LEN)));
		
		const size_t ciphertext_offset =
			VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN;
		
		pipe.process_msg(&ciphertext[ciphertext_offset],
		ciphertext.length - ciphertext_offset);
		
		ubyte computed_mac[MAC_OUTPUT_LEN];
		pipe.read(computed_mac, MAC_OUTPUT_LEN, 1);
		
		if (!same_mem(computed_mac,
		              &ciphertext[VERSION_CODE_LEN + PBKDF_SALT_LEN],
						MAC_OUTPUT_LEN))
			throw new Decoding_Error("CryptoBox integrity failure");
		
		return pipe.read_all_as_string(0);
	}


	/**
	* Decrypt a message encrypted with CryptoBox::encrypt
	* @param input the input data
	* @param passphrase the passphrase used to encrypt the message
	*/
	string decrypt(in string input,
	               in string passphrase)
	{
		return decrypt(cast(const ubyte*)(input[0]),
		               input.length,
		               passphrase);
	}


}

private:
/*
First 24 bits of SHA-256("Botan Cryptobox"), followed by 8 0 bits
for later use as flags, etc if needed
*/
const uint CRYPTOBOX_VERSION_CODE = 0xEFC22400;

const size_t VERSION_CODE_LEN = 4;
const size_t CIPHER_KEY_LEN = 32;
const size_t CIPHER_IV_LEN = 16;
const size_t MAC_KEY_LEN = 32;
const size_t MAC_OUTPUT_LEN = 20;
const size_t PBKDF_SALT_LEN = 10;
const size_t PBKDF_ITERATIONS = 8 * 1024;

const size_t PBKDF_OUTPUT_LEN = CIPHER_KEY_LEN + CIPHER_IV_LEN + MAC_KEY_LEN;