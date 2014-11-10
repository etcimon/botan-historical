/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.dlies;

import botan.pubkey.pubkey;
import botan.mac.mac;
import botan.kdf.kdf;
import botan.utils.xor_buf;

/**
* DLIES Encryption
*/
class DLIES_Encryptor : PK_Encryptor
{
public:
	/*
	* DLIES_Encryptor Constructor
	*/
	this(in PK_Key_Agreement_Key key,
	     KDF kdf_obj,
	     MessageAuthenticationCode mac_obj,
	     size_t mac_key_len = 20)
	{ 
		ka = PK_Key_Agreement(key, "Raw");
		kdf = kdf_obj;
		mac = mac_obj;
		mac_keylen = mac_key_len;
		my_key = key.public_value();
	}

	/*
	* Set the other parties public key
	*/
	void set_other_key(in Vector!ubyte ok)
	{
		other_key = ok;
	}
private:
	/*
	* DLIES Encryption
	*/
	Vector!ubyte enc(in ubyte* input, size_t length,
	                 RandomNumberGenerator) const
	{
		if (length > maximum_input_size())
			throw new Invalid_Argument("DLIES: Plaintext too large");
		if (other_key.empty)
			throw new Invalid_State("DLIES: The other key was never set");
		
		Secure_Vector!ubyte output = Secure_Vector!ubyte(my_key.length + length + mac.output_length);
		buffer_insert(output, 0, my_key);
		buffer_insert(output, my_key.length, input, length);
		
		Secure_Vector!ubyte vz = Secure_Vector!(my_key.ptr, my_key.end());
		vz += ka.derive_key(0, other_key).bits_of();
		
		const size_t K_LENGTH = length + mac_keylen;
		OctetString K = kdf.derive_key(K_LENGTH, vz);
		
		if (K.length != K_LENGTH)
			throw new Encoding_Error("DLIES: KDF did not provide sufficient output");
		ubyte* C = &output[my_key.length];
		
		xor_buf(C, K.ptr + mac_keylen, length);
		mac.set_key(K.ptr, mac_keylen);
		
		mac.update(C, length);
		for (size_t j = 0; j != 8; ++j)
			mac.update(0);
		
		mac.flushInto(C + length);
		
		return unlock(output);
	}

	/*
	* Return the max size, in bytes, of a message
	*/
	size_t maximum_input_size() const
	{
		return 32;
	}

	Vector!ubyte other_key, my_key;

	PK_Key_Agreement ka;
	Unique!KDF kdf;
	Unique!MessageAuthenticationCode mac;
	size_t mac_keylen;
};

/**
* DLIES Decryption
*/
class DLIES_Decryptor : PK_Decryptor
{
public:
	/*
	* DLIES_Decryptor Constructor
	*/
	this(in PK_Key_Agreement_Key key,
	     KDF kdf_obj,
	     MessageAuthenticationCode mac_obj,
	     size_t mac_key_len = 20)
	{
		ka = PK_Key_Agreement(key, "Raw");
		kdf = kdf_obj;
		mac = mac_obj;
		mac_keylen = mac_key_len;
		my_key = key.public_value();
	}

private:
	/*
	* DLIES Decryption
	*/
	Secure_Vector!ubyte dec(in ubyte* msg, size_t length) const
	{
		if (length < my_key.length + mac.output_length)
			throw new Decoding_Error("DLIES decryption: ciphertext is too short");
		
		const size_t CIPHER_LEN = length - my_key.length - mac.output_length;
		
		Vector!ubyte v(msg, msg + my_key.length);
		
		Secure_Vector!ubyte C(msg + my_key.length, msg + my_key.length + CIPHER_LEN);
		
		Secure_Vector!ubyte T(msg + my_key.length + CIPHER_LEN,
		                   msg + my_key.length + CIPHER_LEN + mac.output_length);
		
		Secure_Vector!ubyte vz(msg, msg + my_key.length);
		vz += ka.derive_key(0, v).bits_of();
		
		const size_t K_LENGTH = C.length + mac_keylen;
		OctetString K = kdf.derive_key(K_LENGTH, vz);
		if (K.length != K_LENGTH)
			throw new Encoding_Error("DLIES: KDF did not provide sufficient output");
		
		mac.set_key(K.ptr, mac_keylen);
		mac.update(C);
		for (size_t j = 0; j != 8; ++j)
			mac.update(0);
		Secure_Vector!ubyte T2 = mac.flush();
		if (T != T2)
			throw new Decoding_Error("DLIES: message authentication failed");
		
		xor_buf(C, K.ptr + mac_keylen, C.length);
		
		return C;
	}

	Vector!ubyte my_key;

	PK_Key_Agreement ka;
	Unique!KDF kdf;
	Unique!MessageAuthenticationCode mac;
	size_t mac_keylen;
};
