/*
* Finished Message
* (C) 2004-2006,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_handshake_io.h>
namespace TLS {

namespace {

/*
* Compute the verify_data
*/
Vector!( byte ) finished_compute_verify(in Handshake_State state,
														Connection_Side side)
{
	if (state._version() == Protocol_Version::SSL_V3)
	{
		const(byte)[] SSL_CLIENT_LABEL = { 0x43, 0x4C, 0x4E, 0x54 };
		const(byte)[] SSL_SERVER_LABEL = { 0x53, 0x52, 0x56, 0x52 };

		Handshake_Hash hash = state.hash(); // don't modify state

		Vector!( byte ) ssl3_finished;

		if (side == CLIENT)
			hash.update(SSL_CLIENT_LABEL, sizeof(SSL_CLIENT_LABEL));
		else
			hash.update(SSL_SERVER_LABEL, sizeof(SSL_SERVER_LABEL));

		return unlock(hash.final_ssl3(state.session_keys().master_secret()));
	}
	else
	{
		const(byte)[] TLS_CLIENT_LABEL = {
			0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x69, 0x6E, 0x69,
			0x73, 0x68, 0x65, 0x64 };

		const(byte)[] TLS_SERVER_LABEL = {
			0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6E, 0x69,
			0x73, 0x68, 0x65, 0x64 };

		std::unique_ptr<KDF> prf(state.protocol_specific_prf());

		Vector!( byte ) input;
		if (side == CLIENT)
			input += Pair(TLS_CLIENT_LABEL, sizeof(TLS_CLIENT_LABEL));
		else
			input += Pair(TLS_SERVER_LABEL, sizeof(TLS_SERVER_LABEL));

		input += state.hash().flushInto(state._version(), state.ciphersuite().prf_algo());

		return unlock(prf->derive_key(12, state.session_keys().master_secret(), input));
	}
}

}

/*
* Create a new Finished message
*/
Finished::Finished(Handshake_IO& io,
						 Handshake_State& state,
						 Connection_Side side)
{
	m_verification_data = finished_compute_verify(state, side);
	state.hash().update(io.send(*this));
}

/*
* Serialize a Finished message
*/
Vector!( byte ) Finished::serialize() const
{
	return m_verification_data;
}

/*
* Deserialize a Finished message
*/
Finished::Finished(in Vector!byte buf)
{
	m_verification_data = buf;
}

/*
* Verify a Finished message
*/
bool Finished::verify(in Handshake_State state,
							 Connection_Side side) const
{
	return (m_verification_data == finished_compute_verify(state, side));
}

}

}
