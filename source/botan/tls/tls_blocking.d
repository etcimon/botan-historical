/*
* TLS Blocking API
* (C) 2013 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.tls_blocking;


using namespace std::placeholders;

Blocking_Client::Blocking_Client(size_t delegate(ref ubyte[]) read_fn,
											void delegate(in ubyte[]) write_fn,
											Session_Manager session_manager,
											Credentials_Manager creds,
											in Policy policy,
											RandomNumberGenerator rng,
											in Server_Information server_info,
											in Protocol_Version offer_version,
											string delegate(string[]) next_protocol) :
	m_read_fn(read_fn),
	m_channel(write_fn,
				 std::bind(&Blocking_Client::data_cb, this, _1, _2),
				 std::bind(&Blocking_Client::alert_cb, this, _1, _2, _3),
				 std::bind(&Blocking_Client::handshake_cb, this, _1),
				 session_manager,
				 creds,
				 policy,
				 rng,
				 server_info,
				 offer_version,
				 next_protocol)
{
}

bool Blocking_Client::handshake_cb(in Session session)
{
	return this.handshake_complete(session);
}

void Blocking_Client::alert_cb(const Alert alert, const ubyte[], size_t)
{
	this.alert_notification(alert);
}

void Blocking_Client::data_cb(in ubyte* data, size_t data_len)
{
	m_plaintext.insert(m_plaintext.end(), data, data + data_len);
}

void Blocking_Client::do_handshake()
{
	Vector!ubyte readbuf(4096);

	while(!m_channel.is_closed() && !m_channel.is_active())
	{
		const size_t from_socket = m_read_fn(&readbuf[0], readbuf.length);
		m_channel.received_data(&readbuf[0], from_socket);
	}
}

size_t Blocking_Client::read(ubyte buf[], size_t buf_len)
{
	Vector!ubyte readbuf(4096);

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

}

}