/*
* TLS Blocking API
* (C) 2013 Jack Lloyd
*
* Released under the terms of the botan license.
*/

#include <botan/tls_client.h>
#include <botan/tls_server.h>
#include <deque>
alias secure_deque(T) = Vector!( T, secure_allocator<T>);

namespace TLS {

/**
* Blocking TLS Client
*/
class Blocking_Client
{
	public:

		Blocking_Client(size_t delegate(ref byte[]) read_fn,
							 void delegate(in byte[])> write_fn,
							 Session_Manager session_manager,
							 Credentials_Manager creds,
							 in Policy policy,
							 RandomNumberGenerator rng,
							 in Server_Information server_info = Server_Information(),
							 in Protocol_Version offer_version = Protocol_Version::latest_tls_version(),
							 string delegate(string[]) next_protocol = string.init);

		/**
		* Completes full handshake then returns
		*/
		void do_handshake();

		/**
		* Number of bytes pending read in the plaintext buffer (bytes
		* readable without blocking)
		*/
		size_t pending() const { return m_plaintext.size(); }

		/**
		* Blocking read, will return at least 1 byte or 0 on connection close
		*/
		size_t read(ref byte[] buf);

		void write(in byte* buf) { m_channel.send(buf); }

		TLS::Channel underlying_channel() const { return m_channel; }
		TLS::Channel underlying_channel() { return m_channel; }

		void close() { m_channel.close(); }

		bool is_closed() const { return m_channel.is_closed(); }

		X509_Certificate[] peer_cert_chain() const
		{ return m_channel.peer_cert_chain(); }

		abstract ~Blocking_Client() {}

	protected:
		/**
		* Can override to get the handshake complete notification
		*/
		abstract bool handshake_complete(in Session) { return true; }

		/**
		* Can override to get notification of alerts
		*/
		abstract void alert_notification(in Alert) {}

	private:

		bool handshake_cb(in Session);

		void data_cb(in byte* data);

		void alert_cb(const Alert alert, in byte* data, size_t data_len);

		size_t delegate(ref byte[]) m_read_fn;
		TLS::Client m_channel;
		secure_deque<byte> m_plaintext;
};

}