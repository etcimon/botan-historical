/*
* TLS Session Key
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_session_key;

import botan.algo_base.symkey;
import botan.tls.tls_handshake_state;
import botan.tls.tls_messages;

/**
* TLS Session Keys
*/
struct Session_Keys
{
public:
	SymmetricKey client_cipher_key() const { return c_cipher; }
	SymmetricKey server_cipher_key() const { return s_cipher; }

	SymmetricKey client_mac_key() const { return c_mac; }
	SymmetricKey server_mac_key() const { return s_mac; }

	InitializationVector client_iv() const { return c_iv; }
	InitializationVector server_iv() const { return s_iv; }

	const Secure_Vector!ubyte master_secret() const { return master_sec; }

	@disable this();

	/**
	* Session_Keys Constructor
	*/
	this(const Handshake_State state,
	     in Secure_Vector!ubyte pre_master_secret,
	     bool resuming)
	{
		const size_t cipher_keylen = state.ciphersuite().cipher_keylen();
		const size_t mac_keylen = state.ciphersuite().mac_keylen();
		const size_t cipher_ivlen = state.ciphersuite().cipher_ivlen();
		
		const size_t prf_gen = 2 * (mac_keylen + cipher_keylen + cipher_ivlen);
		
		immutable immutable(ubyte)[] MASTER_SECRET_MAGIC = [
			0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74 ];
		
		immutable immutable(ubyte)[] KEY_GEN_MAGIC = [
			0x6B, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6E, 0x73, 0x69, 0x6F, 0x6E ];
		
		Unique!KDF prf = state.protocol_specific_prf();
		
		if (resuming)
		{
			master_sec = pre_master_secret;
		}
		else
		{
			Secure_Vector!ubyte salt;
			
			if (state._version() != Protocol_Version.SSL_V3)
				salt += Pair(MASTER_SECRET_MAGIC, (MASTER_SECRET_MAGIC).sizeof);
			
			salt += state.client_hello().random();
			salt += state.server_hello().random();
			
			master_sec = prf.derive_key(48, pre_master_secret, salt);
		}
		
		Secure_Vector!ubyte salt;
		if (state._version() != Protocol_Version.SSL_V3)
			salt += Pair(KEY_GEN_MAGIC, (KEY_GEN_MAGIC).sizeof);
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

private:
	Secure_Vector!ubyte master_sec;
	SymmetricKey c_cipher, s_cipher, c_mac, s_mac;
	InitializationVector c_iv, s_iv;
};