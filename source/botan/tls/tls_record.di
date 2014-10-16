/*
* TLS Record Handling
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.tls_magic;
import botan.tls_version;
import botan.aead;
import botan.block.block_cipher;
import botan.stream_cipher;
import botan.mac.mac;
import vector;
import std.datetime;
namespace TLS {

class Ciphersuite;
class Session_Keys;

class Connection_Sequence_Numbers;

/**
* TLS Cipher State
*/
class Connection_Cipher_State
{
	public:
		/**
		* Initialize a new cipher state
		*/
		Connection_Cipher_State(Protocol_Version _version,
										Connection_Side which_side,
										bool is_our_side,
										const Ciphersuite suite,
										const Session_Keys keys);

		AEAD_Mode aead() { return m_aead.get(); }

		const SafeVector!ubyte aead_nonce(ulong seq);

		const SafeVector!ubyte aead_nonce(in ubyte* record);

		const SafeVector!ubyte format_ad(ulong seq, ubyte type,
														 Protocol_Version _version,
														 ushort ptext_length);

		BlockCipher block_cipher() { return m_block_cipher.get(); }

		StreamCipher stream_cipher() { return m_stream_cipher.get(); }

		MessageAuthenticationCode mac() { return m_mac.get(); }

		SafeVector!ubyte cbc_state() { return m_block_cipher_cbc_state; }

		size_t block_size() const { return m_block_size; }

		size_t mac_size() const { return m_mac.output_length(); }

		size_t iv_size() const { return m_iv_size; }

		bool mac_includes_record_version() const { return !m_is_ssl3; }

		bool cipher_padding_single_byte() const { return m_is_ssl3; }

		bool cbc_without_explicit_iv() const
		{ return (m_block_size > 0) && (m_iv_size == 0); }

		Duration age() const
		{
			return Clock.currTime() - m_start_time;
		}

	private:
		SysTime m_start_time;
		Unique!BlockCipher m_block_cipher;
		SafeVector!ubyte m_block_cipher_cbc_state;
		Unique!StreamCipher m_stream_cipher;
		Unique!MessageAuthenticationCode m_mac;

		Unique!AEAD_Mode m_aead;
		SafeVector!ubyte m_nonce, m_ad;

		size_t m_block_size = 0;
		size_t m_iv_size = 0;
		bool m_is_ssl3 = false;
};

/**
* Create a TLS record
* @param write_buffer the output record is placed here
* @param msg_type is the type of the message (handshake, alert, ...)
* @param msg is the plaintext message
* @param msg_length is the length of msg
* @param msg_sequence is the sequence number
* @param _version is the protocol version
* @param cipherstate is the writing cipher state
* @param rng is a random number generator
* @return number of bytes written to write_buffer
*/
void write_record(SafeVector!ubyte write_buffer,
						ubyte msg_type, in ubyte* msg, size_t msg_length,
						Protocol_Version _version,
						ulong msg_sequence,
						Connection_Cipher_State cipherstate,
						RandomNumberGenerator rng);

/**
* Decode a TLS record
* @return zero if full message, else number of bytes still needed
*/
size_t read_record(SafeVector!ubyte read_buffer,
						 in ubyte* input,
						 ref size_t input_consumed,
						 SafeVector!ubyte record,
						 ref ulong record_sequence,
						 Protocol_Version record_version,
						 Record_Type record_type,
						 Connection_Sequence_Numbers sequence_numbers,
						 Connection_Cipher_State delegate(ushort) get_cipherstate);

}