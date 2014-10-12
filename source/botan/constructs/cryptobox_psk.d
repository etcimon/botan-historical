/*
* Cryptobox Message Routines
* (C) 2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.cryptobox_psk;

import string;
import botan.rng;
import botan.algo_base.symkey;
import botan.pipe;
import botan.libstate.lookup;
import botan.loadstor;
/**
* This namespace holds various high-level crypto functions
*/
struct CryptoBox {

	/**
	* Encrypt a message using a shared secret key
	* @param input the input data
	* @param input_len the length of input in bytes
	* @param key the key used to encrypt the message
	* @param rng a ref to a random number generator, such as AutoSeeded_RNG
	*/
	static Vector!ubyte encrypt(in ubyte* input, size_t input_len,
	                            ref const SymmetricKey master_key,
	                            RandomNumberGenerator rng)
	{
		Unique!KDF kdf = get_kdf(CRYPTOBOX_KDF);
		
		const SafeVector!ubyte cipher_key_salt =
			rng.random_vec(KEY_KDF_SALT_LENGTH);
		
		const SafeVector!ubyte mac_key_salt =
			rng.random_vec(KEY_KDF_SALT_LENGTH);
		
		SymmetricKey cipher_key =
			kdf.derive_key(CIPHER_KEY_LENGTH,
			               master_key.bits_of(),
			               cipher_key_salt);
		
		SymmetricKey mac_key =
			kdf.derive_key(MAC_KEY_LENGTH,
			               master_key.bits_of(),
			               mac_key_salt);
		
		InitializationVector cipher_iv = InitializationVector(rng, 16);
		
		Unique!MessageAuthenticationCode mac = get_mac(CRYPTOBOX_MAC);
		mac.set_key(mac_key);
		
		Pipe pipe = Pipe(get_cipher(CRYPTOBOX_CIPHER, cipher_key, cipher_iv, ENCRYPTION));
		pipe.process_msg(input, input_len);
		SafeVector!ubyte ctext = pipe.read_all(0);
		
		Vector!ubyte output = Vector!ubyte(MAGIC_LENGTH);
		store_be(CRYPTOBOX_MAGIC, &output[0]);
		output += cipher_key_salt;
		output += mac_key_salt;
		output += cipher_iv.bits_of();
		output += ctext;
		
		mac.update(output);
		
		output += mac.flush();
		return output;
	}


	/**
	* Encrypt a message using a shared secret key
	* @param input the input data
	* @param input_len the length of input in bytes
	* @param key the key used to encrypt the message
	* @param rng a ref to a random number generator, such as AutoSeeded_RNG
	*/
	static SafeVector!ubyte decrypt(in ubyte* input, size_t input_len,
	                                ref const SymmetricKey master_key)
	{
		const size_t MIN_CTEXT_SIZE = 16; // due to using CBC with padding
		
		const size_t MIN_POSSIBLE_LENGTH =
			MAGIC_LENGTH +
				2 * KEY_KDF_SALT_LENGTH +
				CIPHER_IV_LENGTH +
				MIN_CTEXT_SIZE +
				MAC_OUTPUT_LENGTH;
		
		if (input_len < MIN_POSSIBLE_LENGTH)
			throw new Decoding_Error("Encrypted input too short to be valid");
		
		if (load_be!uint(input, 0) != CRYPTOBOX_MAGIC)
			throw new Decoding_Error("Unknown header value in cryptobox");
		
		Unique!KDF kdf = get_kdf(CRYPTOBOX_KDF);
		
		const ubyte* cipher_key_salt = &input[MAGIC_LENGTH];
		
		const ubyte* mac_key_salt = &input[MAGIC_LENGTH + KEY_KDF_SALT_LENGTH];
		
		SymmetricKey mac_key = kdf.derive_key(MAC_KEY_LENGTH,
		                                      master_key.bits_of(),
		                                      mac_key_salt,
		                                      KEY_KDF_SALT_LENGTH);
		
		Unique!MessageAuthenticationCode mac = get_mac(CRYPTOBOX_MAC);
		mac.set_key(mac_key);
		
		mac.update(&input[0], input_len - MAC_OUTPUT_LENGTH);
		SafeVector!ubyte computed_mac = mac.flush();
		
		if (!same_mem(&input[input_len - MAC_OUTPUT_LENGTH], &computed_mac[0], computed_mac.size()))
			throw new Decoding_Error("MAC verification failed");
		
		SymmetricKey cipher_key =
			kdf.derive_key(CIPHER_KEY_LENGTH,
			               master_key.bits_of(),
			               cipher_key_salt, KEY_KDF_SALT_LENGTH);
		
		InitializationVector cipher_iv = InitializationVector(&input[MAGIC_LENGTH+2*KEY_KDF_SALT_LENGTH],
		CIPHER_IV_LENGTH);
		
		const size_t CTEXT_OFFSET = MAGIC_LENGTH + 2 * KEY_KDF_SALT_LENGTH + CIPHER_IV_LENGTH;
		
		Pipe pipe = Pipe(get_cipher(CRYPTOBOX_CIPHER, cipher_key, cipher_iv, DECRYPTION));
		pipe.process_msg(&input[CTEXT_OFFSET],
		input_len - (MAC_OUTPUT_LENGTH + CTEXT_OFFSET));
		return pipe.read_all();
	}

}
	

private:

const uint CRYPTOBOX_MAGIC = 0x571B0E4F;
const string CRYPTOBOX_CIPHER = "AES-256/CBC";
const string CRYPTOBOX_MAC = "HMAC(SHA-256)";
const string CRYPTOBOX_KDF = "KDF2(SHA-256)";

const size_t MAGIC_LENGTH = 4;
const size_t KEY_KDF_SALT_LENGTH = 10;
const size_t MAC_KEY_LENGTH = 32;
const size_t CIPHER_KEY_LENGTH = 32;
const size_t CIPHER_IV_LENGTH = 16;
const size_t MAC_OUTPUT_LENGTH = 32;
