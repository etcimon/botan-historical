/*
* TLS Heartbeats
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

#include <botan/secmem.h>
namespace TLS {

/**
* TLS Heartbeat message
*/
class Heartbeat_Message
{
	public:
		enum Type { REQUEST = 1, RESPONSE = 2 };

		std::vector<byte> contents() const;

		in Array!byte payload() const { return m_payload; }

		bool is_request() const { return m_type == REQUEST; }

		Heartbeat_Message(in Array!byte buf);

		Heartbeat_Message(Type type, in byte[] payload, size_t payload_len);
	private:
		Type m_type;
		std::vector<byte> m_payload;
};

}