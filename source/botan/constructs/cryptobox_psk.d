/*
* Cryptobox Message Routines
* (C) 2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.cryptobox_psk;

// import string;
import botan.rng.rng;
import botan.algo_base.symkey;
import botan.filters.pipe;
import botan.libstate.lookup;
import botan.mac.mac;
import botan.utils.loadstor;
import botan.utils.types;
/**
* This namespace holds various high-level crypto functions
*/
struct CryptoBox {

    /**
    * Encrypt a message using a shared secret key
    * @param input = the input data
    * @param input_len = the length of input in bytes
    * @param key = the key used to encrypt the message
    * @param rng = a ref to a random number generator, such as AutoSeeded_RNG
    */
    static Vector!ubyte encrypt(in ubyte* input, size_t input_len,
                                in SymmetricKey master_key,
                                RandomNumberGenerator rng)
    {
        Unique!KDF kdf = get_kdf(CRYPTOBOX_KDF);
        
        const Secure_Vector!ubyte cipher_key_salt = rng.random_vec(KEY_KDF_SALT_LENGTH);
        
        const Secure_Vector!ubyte mac_key_salt = rng.random_vec(KEY_KDF_SALT_LENGTH);
        
        SymmetricKey cipher_key = kdf.derive_key(CIPHER_KEY_LENGTH, master_key.bits_of(), cipher_key_salt);
        
        SymmetricKey mac_key = kdf.derive_key(MAC_KEY_LENGTH, master_key.bits_of(), mac_key_salt);
        
        InitializationVector cipher_iv = InitializationVector(rng, 16);
        
        Unique!MessageAuthenticationCode mac = get_mac(CRYPTOBOX_MAC);
        mac.set_key(mac_key);
        
        Pipe pipe = Pipe(get_cipher(CRYPTOBOX_CIPHER, cipher_key, cipher_iv, ENCRYPTION));
        pipe.process_msg(input, input_len);
        Secure_Vector!ubyte ctext = pipe.read_all(0);
        
        Secure_Vector!ubyte output = Secure_Vector!ubyte(MAGIC_LENGTH);
        store_bigEndian(CRYPTOBOX_MAGIC, output.ptr);
        output ~= cipher_key_salt;
        output ~= mac_key_salt;
        output ~= cipher_iv.bits_of();
        output ~= ctext;

        mac.update(output);
        
        output ~= mac.finished();
        return output.unlock();
    }

    /**
    * Encrypt a message using a shared secret key
    * @param input = the input data
    * @param input_len = the length of input in bytes
    * @param key = the key used to encrypt the message
    * @param rng = a ref to a random number generator, such as AutoSeeded_RNG
    */
    static Secure_Vector!ubyte decrypt(in ubyte* input, size_t input_len, in SymmetricKey master_key)
    {
        __gshared immutable size_t MIN_CTEXT_SIZE = 16; // due to using CBC with padding
        
        __gshared immutable size_t MIN_POSSIBLE_LENGTH = MAGIC_LENGTH + 2 * KEY_KDF_SALT_LENGTH + CIPHER_IV_LENGTH + 
                                                         MIN_CTEXT_SIZE + MAC_OUTPUT_LENGTH;
        
        if (input_len < MIN_POSSIBLE_LENGTH)
            throw new Decoding_Error("Encrypted input too short to be valid");
        
        if (load_bigEndian!uint(input, 0) != CRYPTOBOX_MAGIC)
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
        
        mac.update(input.ptr, input_len - MAC_OUTPUT_LENGTH);
        Secure_Vector!ubyte computed_mac = mac.finished();
        
        if (!same_mem(&input[input_len - MAC_OUTPUT_LENGTH], computed_mac.ptr, computed_mac.length))
            throw new Decoding_Error("MAC verification failed");
        
        SymmetricKey cipher_key = kdf.derive_key(CIPHER_KEY_LENGTH, master_key.bits_of(), cipher_key_salt, KEY_KDF_SALT_LENGTH);
        
        InitializationVector cipher_iv = InitializationVector(&input[MAGIC_LENGTH+2*KEY_KDF_SALT_LENGTH], CIPHER_IV_LENGTH);
        
        const size_t CTEXT_OFFSET = MAGIC_LENGTH + 2 * KEY_KDF_SALT_LENGTH + CIPHER_IV_LENGTH;
        
        Pipe pipe = Pipe(get_cipher(CRYPTOBOX_CIPHER, cipher_key, cipher_iv, DECRYPTION));
        pipe.process_msg(&input[CTEXT_OFFSET],
        input_len - (MAC_OUTPUT_LENGTH + CTEXT_OFFSET));
        return pipe.read_all();
    }

}

private:

__gshared immutable uint CRYPTOBOX_MAGIC = 0x571B0E4F;
__gshared immutable string CRYPTOBOX_CIPHER = "AES-256/CBC";
__gshared immutable string CRYPTOBOX_MAC = "HMAC(SHA-256)";
__gshared immutable string CRYPTOBOX_KDF = "KDF2(SHA-256)";

__gshared immutable size_t MAGIC_LENGTH = 4;
__gshared immutable size_t KEY_KDF_SALT_LENGTH = 10;
__gshared immutable size_t MAC_KEY_LENGTH = 32;
__gshared immutable size_t CIPHER_KEY_LENGTH = 32;
__gshared immutable size_t CIPHER_IV_LENGTH = 16;
__gshared immutable size_t MAC_OUTPUT_LENGTH = 32;
