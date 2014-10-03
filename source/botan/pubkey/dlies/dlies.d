/*
* DLIES
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.dlies;
import botan.internal.xor_buf;
/*
* DLIES_Encryptor Constructor
*/
DLIES_Encryptor::DLIES_Encryptor(in PK_Key_Agreement_Key key,
											KDF* kdf_obj,
											MessageAuthenticationCode mac_obj,
											size_t mac_kl) :
	ka(key, "Raw"),
	kdf(kdf_obj),
	mac(mac_obj),
	mac_keylen(mac_kl)
{
	my_key = key.public_value();
}

/*
* DLIES Encryption
*/
Vector!byte DLIES_Encryptor::enc(in byte* input, size_t length,
													RandomNumberGenerator) const
{
	if (length > maximum_input_size())
		throw new Invalid_Argument("DLIES: Plaintext too large");
	if (other_key.empty())
		throw new Invalid_State("DLIES: The other key was never set");

	SafeVector!byte output(my_key.size() + length + mac.output_length());
	buffer_insert(output, 0, my_key);
	buffer_insert(output, my_key.size(), input, length);

	SafeVector!byte vz(my_key.begin(), my_key.end());
	vz += ka.derive_key(0, other_key).bits_of();

	const size_t K_LENGTH = length + mac_keylen;
	OctetString K = kdf.derive_key(K_LENGTH, vz);

	if (K.length() != K_LENGTH)
		throw new Encoding_Error("DLIES: KDF did not provide sufficient output");
	byte* C = &output[my_key.size()];

	xor_buf(C, K.begin() + mac_keylen, length);
	mac.set_key(K.begin(), mac_keylen);

	mac.update(C, length);
	for (size_t j = 0; j != 8; ++j)
		mac.update(0);

	mac.flushInto(C + length);

	return unlock(output);
}

/*
* Set the other parties public key
*/
void DLIES_Encryptor::set_other_key(in Vector!byte ok)
{
	other_key = ok;
}

/*
* Return the max size, in bytes, of a message
*/
size_t DLIES_Encryptor::maximum_input_size() const
{
	return 32;
}

/*
* DLIES_Decryptor Constructor
*/
DLIES_Decryptor::DLIES_Decryptor(in PK_Key_Agreement_Key key,
											KDF* kdf_obj,
											MessageAuthenticationCode mac_obj,
											size_t mac_kl) :
	ka(key, "Raw"),
	kdf(kdf_obj),
	mac(mac_obj),
	mac_keylen(mac_kl)
{
	my_key = key.public_value();
}

/*
* DLIES Decryption
*/
SafeVector!byte DLIES_Decryptor::dec(in byte* msg, size_t length) const
{
	if (length < my_key.size() + mac.output_length())
		throw new Decoding_Error("DLIES decryption: ciphertext is too short");

	const size_t CIPHER_LEN = length - my_key.size() - mac.output_length();

	Vector!byte v(msg, msg + my_key.size());

	SafeVector!byte C(msg + my_key.size(), msg + my_key.size() + CIPHER_LEN);

	SafeVector!byte T(msg + my_key.size() + CIPHER_LEN,
								 msg + my_key.size() + CIPHER_LEN + mac.output_length());

	SafeVector!byte vz(msg, msg + my_key.size());
	vz += ka.derive_key(0, v).bits_of();

	const size_t K_LENGTH = C.size() + mac_keylen;
	OctetString K = kdf.derive_key(K_LENGTH, vz);
	if (K.length() != K_LENGTH)
		throw new Encoding_Error("DLIES: KDF did not provide sufficient output");

	mac.set_key(K.begin(), mac_keylen);
	mac.update(C);
	for (size_t j = 0; j != 8; ++j)
		mac.update(0);
	SafeVector!byte T2 = mac.flush();
	if (T != T2)
		throw new Decoding_Error("DLIES: message authentication failed");

	xor_buf(C, K.begin() + mac_keylen, C.size());

	return C;
}

}
