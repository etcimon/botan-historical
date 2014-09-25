/*
* TLS Record Handling
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/mac.h>
#include <vector>
#include <chrono>
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

		const SafeVector!byte aead_nonce(u64bit seq);

		const SafeVector!byte aead_nonce(in byte[] record);

		const SafeVector!byte format_ad(u64bit seq, byte type,
														 Protocol_Version _version,
														 u16bit ptext_length);

		BlockCipher* block_cipher() { return m_block_cipher.get(); }

		StreamCipher stream_cipher() { return m_stream_cipher.get(); }

		MessageAuthenticationCode mac() { return m_mac.get(); }

		SafeVector!byte cbc_state() { return m_block_cipher_cbc_state; }

		size_t block_size() const { return m_block_size; }

		size_t mac_size() const { return m_mac->output_length(); }

		size_t iv_size() const { return m_iv_size; }

		bool mac_includes_record_version() const { return !m_is_ssl3; }

		bool cipher_padding_single_byte() const { return m_is_ssl3; }

		bool cbc_without_explicit_iv() const
		{ return (m_block_size > 0) && (m_iv_size == 0); }

		std::chrono::seconds age() const
		{
			return std::chrono::duration_cast(<std::chrono::seconds>)(
				std::chrono::system_clock::now() - m_start_time);
		}

	private:
		SysTime m_start_time;
		std::unique_ptr<BlockCipher> m_block_cipher;
		SafeVector!byte m_block_cipher_cbc_state;
		std::unique_ptr<StreamCipher> m_stream_cipher;
		std::unique_ptr<MessageAuthenticationCode> m_mac;

		std::unique_ptr<AEAD_Mode> m_aead;
		SafeVector!byte m_nonce, m_ad;

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
void write_record(SafeVector!byte write_buffer,
						byte msg_type, in byte[] msg, size_t msg_length,
						Protocol_Version _version,
						u64bit msg_sequence,
						Connection_Cipher_State cipherstate,
						RandomNumberGenerator rng);

/**
* Decode a TLS record
* @return zero if full message, else number of bytes still needed
*/
size_t read_record(SafeVector!byte read_buffer,
						 in byte[] input,
						 ref size_t input_consumed,
						 SafeVector!byte record,
						 ref u64bit record_sequence,
						 Protocol_Version record_version,
						 Record_Type record_type,
						 Connection_Sequence_Numbers sequence_numbers,
						 Connection_Cipher_State delegate(u16bit) get_cipherstate);

}