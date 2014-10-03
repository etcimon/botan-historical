/*
* TLS Heartbeats
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.alloc.secmem;
namespace TLS {

/**
* TLS Heartbeat message
*/
class Heartbeat_Message
{
	public:
		enum Type { REQUEST = 1, RESPONSE = 2 };

		Vector!byte contents() const;

		in Vector!byte payload() const { return m_payload; }

		bool is_request() const { return m_type == REQUEST; }

		Heartbeat_Message(in Vector!byte buf);

		Heartbeat_Message(Type type, in byte* payload, size_t payload_len);
	private:
		Type m_type;
		Vector!byte m_payload;
};

}