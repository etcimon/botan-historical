/*
* Client Key Exchange Message
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.internal.tls_messages;
import botan.internal.tls_reader;
import botan.internal.tls_extensions;
import botan.internal.tls_handshake_io;
import botan.credentials_manager;
import botan.pubkey;
import botan.dh;
import botan.ecdh;
import botan.rsa;
import botan.srp6;
import botan.rng;
import botan.loadstor;
namespace TLS {

namespace {

SafeVector!ubyte strip_leading_zeros(in SafeVector!ubyte input)
{
	size_t leading_zeros = 0;

	for (size_t i = 0; i != input.size(); ++i)
	{
		if (input[i] != 0)
			break;
		++leading_zeros;
	}

	SafeVector!ubyte output(&input[leading_zeros],
										&input[input.size()]);
	return output;
}

}

/*
* Create a new Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(Handshake_IO& io,
													  Handshake_State& state,
													  const Policy& policy,
													  Credentials_Manager& creds,
													  const Public_Key server_public_key,
													  in string hostname,
													  RandomNumberGenerator rng)
{
	const string kex_algo = state.ciphersuite().kex_algo();

	if (kex_algo == "PSK")
	{
		string identity_hint = "";

		if (state.server_kex())
		{
			TLS_Data_Reader reader("ClientKeyExchange", state.server_kex().params());
			identity_hint = reader.get_string(2, 0, 65535);
		}

		const string hostname = state.client_hello().sni_hostname();

		const string psk_identity = creds.psk_identity("tls-client",
																			 hostname,
																			 identity_hint);

		append_tls_length_value(m_key_material, psk_identity, 2);

		SymmetricKey psk = creds.psk("tls-client", hostname, psk_identity);

		Vector!ubyte zeros(psk.length());

		append_tls_length_value(m_pre_master, zeros, 2);
		append_tls_length_value(m_pre_master, psk.bits_of(), 2);
	}
	else if (state.server_kex())
	{
		TLS_Data_Reader reader("ClientKeyExchange", state.server_kex().params());

		SymmetricKey psk;

		if (kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
		{
			string identity_hint = reader.get_string(2, 0, 65535);

			const string hostname = state.client_hello().sni_hostname();

			const string psk_identity = creds.psk_identity("tls-client",
																				 hostname,
																				 identity_hint);

			append_tls_length_value(m_key_material, psk_identity, 2);

			psk = creds.psk("tls-client", hostname, psk_identity);
		}

		if (kex_algo == "DH" || kex_algo == "DHE_PSK")
		{
			BigInt p = BigInt::decode(reader.get_range!ubyte(2, 1, 65535));
			BigInt g = BigInt::decode(reader.get_range!ubyte(2, 1, 65535));
			BigInt Y = BigInt::decode(reader.get_range!ubyte(2, 1, 65535));

			if (reader.remaining_bytes())
				throw new Decoding_Error("Bad params size for DH key exchange");

			if (p.bits() < policy.minimum_dh_group_size())
				throw new TLS_Exception(Alert::INSUFFICIENT_SECURITY,
										  "Server sent DH group of " ~
										  std.conv.to!string(p.bits()) +
										  " bits, policy requires at least " ~
										  std.conv.to!string(policy.minimum_dh_group_size()));

			/*
			* A basic check for key validity. As we do not know q here we
			* cannot check that Y is in the right subgroup. However since
			* our key is ephemeral there does not seem to be any
			* advantage to bogus keys anyway.
			*/
			if (Y <= 1 || Y >= p - 1)
				throw new TLS_Exception(Alert::INSUFFICIENT_SECURITY,
										  "Server sent bad DH key for DHE exchange");

			DL_Group group(p, g);

			if (!group.verify_group(rng, true))
				throw new Internal_Error("DH group failed validation, possible attack");

			DH_PublicKey counterparty_key(group, Y);

			DH_PrivateKey priv_key(rng, group);

			PK_Key_Agreement ka(priv_key, "Raw");

			SafeVector!ubyte dh_secret = strip_leading_zeros(
				ka.derive_key(0, counterparty_key.public_value()).bits_of());

			if (kex_algo == "DH")
				m_pre_master = dh_secret;
			else
			{
				append_tls_length_value(m_pre_master, dh_secret, 2);
				append_tls_length_value(m_pre_master, psk.bits_of(), 2);
			}

			append_tls_length_value(m_key_material, priv_key.public_value(), 2);
		}
		else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
		{
			const ubyte curve_type = reader.get_byte();

			if (curve_type != 3)
				throw new Decoding_Error("Server sent non-named ECC curve");

			const ushort curve_id = reader.get_ushort();

			const string name = Supported_Elliptic_Curves::curve_id_to_name(curve_id);

			if (name == "")
				throw new Decoding_Error("Server sent unknown named curve " ~ std.conv.to!string(curve_id));

			EC_Group group(name);

			Vector!ubyte ecdh_key = reader.get_range!ubyte(1, 1, 255);

			ECDH_PublicKey counterparty_key(group, OS2ECP(ecdh_key, group.get_curve()));

			ECDH_PrivateKey priv_key(rng, group);

			PK_Key_Agreement ka(priv_key, "Raw");

			SafeVector!ubyte ecdh_secret =
				ka.derive_key(0, counterparty_key.public_value()).bits_of();

			if (kex_algo == "ECDH")
				m_pre_master = ecdh_secret;
			else
			{
				append_tls_length_value(m_pre_master, ecdh_secret, 2);
				append_tls_length_value(m_pre_master, psk.bits_of(), 2);
			}

			append_tls_length_value(m_key_material, priv_key.public_value(), 1);
		}
		else if (kex_algo == "SRP_SHA")
		{
			const BigInt N = BigInt::decode(reader.get_range!ubyte(2, 1, 65535));
			const BigInt g = BigInt::decode(reader.get_range!ubyte(2, 1, 65535));
			Vector!ubyte salt = reader.get_range!ubyte(1, 1, 255);
			const BigInt B = BigInt::decode(reader.get_range!ubyte(2, 1, 65535));

			const string srp_group = srp6_group_identifier(N, g);

			const string srp_identifier =
				creds.srp_identifier("tls-client", hostname);

			const string srp_password =
				creds.srp_password("tls-client", hostname, srp_identifier);

			Pair!(BigInt, SymmetricKey) srp_vals =
				srp6_client_agree(srp_identifier,
										srp_password,
										srp_group,
										"SHA-1",
										salt,
										B,
										rng);

			append_tls_length_value(m_key_material, BigInt::encode(srp_vals.first), 2);
			m_pre_master = srp_vals.second.bits_of();
		}
		else
		{
			throw new Internal_Error("Client_Key_Exchange: Unknown kex " ~
										kex_algo);
		}

		reader.assert_done();
	}
	else
	{
		// No server key exchange msg better mean RSA kex + RSA key in cert

		if (kex_algo != "RSA")
			throw new Unexpected_Message("No server kex but negotiated kex " ~ kex_algo);

		if (!server_public_key)
			throw new Internal_Error("No server public key for RSA exchange");

		if (auto rsa_pub = cast(const RSA_PublicKey*)(server_public_key))
		{
			const Protocol_Version offered_version = state.client_hello()._version();

			m_pre_master = rng.random_vec(48);
			m_pre_master[0] = offered_version.major_version();
			m_pre_master[1] = offered_version.minor_version();

			PK_Encryptor_EME encryptor(*rsa_pub, "PKCS1v15");

			Vector!ubyte encrypted_key = encryptor.encrypt(m_pre_master, rng);

			if (state._version() == Protocol_Version::SSL_V3)
				m_key_material = encrypted_key; // no length field
			else
				append_tls_length_value(m_key_material, encrypted_key, 2);
		}
		else
			throw new TLS_Exception(Alert::HANDSHAKE_FAILURE,
									  "Expected a RSA key in server cert but got " ~
									  server_public_key.algo_name());
	}

	state.hash().update(io.send(*this));
}

/*
* Read a Client Key Exchange message
*/
Client_Key_Exchange::Client_Key_Exchange(in Vector!ubyte contents,
													  const Handshake_State& state,
													  const Private_Key server_rsa_kex_key,
													  Credentials_Manager& creds,
													  const Policy& policy,
													  RandomNumberGenerator rng)
{
	const string kex_algo = state.ciphersuite().kex_algo();

	if (kex_algo == "RSA")
	{
		BOTAN_ASSERT(state.server_certs() && !state.server_certs().cert_chain().empty(),
						 "RSA key exchange negotiated so server sent a certificate");

		if (!server_rsa_kex_key)
			throw new Internal_Error("Expected RSA kex but no server kex key set");

		if (!cast(const RSA_PrivateKey*)(server_rsa_kex_key))
			throw new Internal_Error("Expected RSA key but got " ~ server_rsa_kex_key.algo_name());

		PK_Decryptor_EME decryptor(*server_rsa_kex_key, "PKCS1v15");

		Protocol_Version client_version = state.client_hello()._version();

		/*
		* This is used as the pre-master if RSA decryption fails.
		* Otherwise we can be used as an oracle. See Bleichenbacher
		* "Chosen Ciphertext Attacks against Protocols Based on RSA
		* Encryption Standard PKCS #1", Crypto 98
		*
		* Create it here instead if in the catch clause as otherwise we
		* expose a timing channel WRT the generation of the fake value.
		* Some timing channel likely remains due to exception handling
		* and the like.
		*/
		SafeVector!ubyte fake_pre_master = rng.random_vec(48);
		fake_pre_master[0] = client_version.major_version();
		fake_pre_master[1] = client_version.minor_version();

		try
		{
			if (state._version() == Protocol_Version::SSL_V3)
			{
				m_pre_master = decryptor.decrypt(contents);
			}
			else
			{
				TLS_Data_Reader reader("ClientKeyExchange", contents);
				m_pre_master = decryptor.decrypt(reader.get_range!ubyte(2, 0, 65535));
			}

			if (m_pre_master.size() != 48 ||
				client_version.major_version() != m_pre_master[0] ||
				client_version.minor_version() != m_pre_master[1])
			{
				throw new Decoding_Error("Client_Key_Exchange: Secret corrupted");
			}
		}
		catch
		{
			m_pre_master = fake_pre_master;
		}
	}
	else
	{
		TLS_Data_Reader reader("ClientKeyExchange", contents);

		SymmetricKey psk;

		if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
		{
			const string psk_identity = reader.get_string(2, 0, 65535);

			psk = creds.psk("tls-server",
								 state.client_hello().sni_hostname(),
								 psk_identity);

			if (psk.length() == 0)
			{
				if (policy.hide_unknown_users())
					psk = SymmetricKey(rng, 16);
				else
					throw new TLS_Exception(Alert::UNKNOWN_PSK_IDENTITY,
											  "No PSK for identifier " ~ psk_identity);
			}
		}

		if (kex_algo == "PSK")
		{
			Vector!ubyte zeros(psk.length());
			append_tls_length_value(m_pre_master, zeros, 2);
			append_tls_length_value(m_pre_master, psk.bits_of(), 2);
		}
		else if (kex_algo == "SRP_SHA")
		{
			SRP6_Server_Session& srp = state.server_kex().server_srp_params();

			m_pre_master = srp.step2(BigInt::decode(reader.get_range!ubyte(2, 0, 65535))).bits_of();
		}
		else if (kex_algo == "DH" || kex_algo == "DHE_PSK" ||
				  kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
		{
			in Private_Key Private_Key = state.server_kex().server_kex_key();

			const PK_Key_Agreement_Key* ka_key =
				cast(in PK_Key_Agreement_Key*)(Private_Key);

			if (!ka_key)
				throw new Internal_Error("Expected key agreement key type but got " ~
											Private_Key.algo_name());

			try
			{
				PK_Key_Agreement ka(*ka_key, "Raw");

				Vector!ubyte client_pubkey;

				if (ka_key.algo_name() == "DH")
					client_pubkey = reader.get_range!ubyte(2, 0, 65535);
				else
					client_pubkey = reader.get_range!ubyte(1, 0, 255);

				SafeVector!ubyte shared_secret = ka.derive_key(0, client_pubkey).bits_of();

				if (ka_key.algo_name() == "DH")
					shared_secret = strip_leading_zeros(shared_secret);

				if (kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
				{
					append_tls_length_value(m_pre_master, shared_secret, 2);
					append_tls_length_value(m_pre_master, psk.bits_of(), 2);
				}
				else
					m_pre_master = shared_secret;
			}
			catch(std::exception &e)
			{
				/*
				* Something failed in the DH computation. To avoid possible
				* timing attacks, randomize the pre-master output and carry
				* on, allowing the protocol to fail later in the finished
				* checks.
				*/
				m_pre_master = rng.random_vec(ka_key.public_value().size());
			}
		}
		else
			throw new Internal_Error("Client_Key_Exchange: Unknown kex type " ~ kex_algo);
	}
}

}

}
