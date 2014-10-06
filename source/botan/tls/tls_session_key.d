/*
* TLS Session Key
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_session_key;
import botan.internal.tls_handshake_state;
import botan.internal.tls_messages;
namespace TLS {

/**
* Session_Keys Constructor
*/
Session_Keys::Session_Keys(const Handshake_State* state,
									in SafeVector!ubyte pre_master_secret,
									bool resuming)
{
	const size_t cipher_keylen = state.ciphersuite().cipher_keylen();
	const size_t mac_keylen = state.ciphersuite().mac_keylen();
	const size_t cipher_ivlen = state.ciphersuite().cipher_ivlen();

	const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_ivlen);

	const(ubyte)[] MASTER_SECRET_MAGIC = {
		0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 };

	const(ubyte)[] KEY_GEN_MAGIC = {
		0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E };

	Unique!KDF prf = state.protocol_specific_prf();

	if (resuming)
	{
		master_sec = pre_master_secret;
	}
	else
	{
		SafeVector!ubyte salt;

		if (state.version() != Protocol_Version::SSL_V3)
			salt += Pair(MASTER_SECRET_MAGIC, sizeof(MASTER_SECRET_MAGIC));

		salt += state.client_hello().random();
		salt += state.server_hello().random();

		master_sec = prf.derive_key(48, pre_master_secret, salt);
	}

	SafeVector!ubyte salt;
	if (state.version() != Protocol_Version::SSL_V3)
		salt += Pair(KEY_GEN_MAGIC, sizeof(KEY_GEN_MAGIC));
	salt += state.server_hello().random();
	salt += state.client_hello().random();

	SymmetricKey keyblock = prf.derive_key(prf_gen, master_sec, salt);

	const ubyte* key_data = keyblock.begin();

	c_mac = SymmetricKey(key_data, mac_keylen);
	key_data += mac_keylen;

	s_mac = SymmetricKey(key_data, mac_keylen);
	key_data += mac_keylen;

	c_cipher = SymmetricKey(key_data, cipher_keylen);
	key_data += cipher_keylen;

	s_cipher = SymmetricKey(key_data, cipher_keylen);
	key_data += cipher_keylen;

	c_iv = InitializationVector(key_data, cipher_ivlen);
	key_data += cipher_ivlen;

	s_iv = InitializationVector(key_data, cipher_ivlen);
}

}

}
