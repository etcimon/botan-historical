/*
* TLS Blocking API
* (C) 2013 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_blocking;

import botan.tls_client;
import botan.tls_server;
import deque;

alias secure_deque(T) = Vector!( T, secure_allocator!T);

/**
* Blocking TLS Client
*/
final class Blocking_Client
{
public:
	this(size_t delegate(ref ubyte[]) read_fn,
	     void delegate(in ubyte[]) write_fn,
	     Session_Manager session_manager,
	     Credentials_Manager creds,
	     in Policy policy,
	     RandomNumberGenerator rng,
	     in Server_Information server_info = Server_Information(),
	     in Protocol_Version offer_version = Protocol_Version.latest_tls_version(),
	     string delegate(string[]) next_protocol = null)
	{
		m_read_fn = read_fn;
		m_channel = new Channel(write_fn, &data_cb, &alert_cb, &handshake_cb, session_manager, creds,
		                        policy, rng, server_info, offer_version, next_protocol);
	}

	/**
	* Completes full handshake then returns
	*/
	void do_handshake()
	{
		Vector!ubyte readbuf = Vector!ubyte(4096);
		
		while(!m_channel.is_closed() && !m_channel.is_active())
		{
			const size_t from_socket = m_read_fn(readbuf[]);
			m_channel.received_data(&readbuf[0], from_socket);
		}
	}

	/**
	* Number of bytes pending read in the plaintext buffer (bytes
	* readable without blocking)
	*/
	size_t pending() const { return m_plaintext.length; }

	/**
	* Blocking read, will return at least 1 ubyte or 0 on connection close
	*/
	size_t read(ubyte* buf, size_t buf_len)
	{
		Vector!ubyte readbuf = Vector!ubyte(4096);
		
		while(m_plaintext.empty() && !m_channel.is_closed())
		{
			const size_t from_socket = m_read_fn(&readbuf[0], readbuf.length);
			m_channel.received_data(&readbuf[0], from_socket);
		}
		
		const size_t returned = std.algorithm.min(buf_len, m_plaintext.length);
		
		for (size_t i = 0; i != returned; ++i)
			buf[i] = m_plaintext[i];
		m_plaintext.erase(m_plaintext.begin(), m_plaintext.begin() + returned);
		
		BOTAN_ASSERT_IMPLICATION(returned == 0, m_channel.is_closed(),
		                         "Only return zero if channel is closed");
		
		return returned;
	}

	void write(in ubyte* buf) { m_channel.send(buf); }

	Channel underlying_channel() const { return m_channel; }
	Channel underlying_channel() { return m_channel; }

	void close() { m_channel.close(); }

	bool is_closed() const { return m_channel.is_closed(); }

	X509_Certificate[] peer_cert_chain() const
	{ return m_channel.peer_cert_chain(); }

	~this() {}

package:
	/**
	 * Can to get the handshake complete notification override
	*/
	abstract bool handshake_complete(in Session) { return true; }

	/**
	* Can to get notification of alerts override
	*/
	abstract void alert_notification(in Alert) {}

private:

	bool handshake_cb(in Session session)
	{
		return this.handshake_complete(session);
	}

	void data_cb(in ubyte[] data)
	{
		m_plaintext.insert(m_plaintext.end(), data.ptr, data.length);
	}

	void alert_cb(const Alert alert, in ubyte[])
	{
		this.alert_notification(alert);
	}

	size_t delegate(ref ubyte[]) m_read_fn;
	Client m_channel;
	secure_deque!ubyte m_plaintext;
};