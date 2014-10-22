/*
* TLS Heartbeats
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_heartbeats;

import botan.alloc.secmem;
import botan.tls.tls_extensions;
import botan.tls.tls_reader;
import botan.tls.tls_exceptn;

/**
* TLS Heartbeat message
*/
class Heartbeat_Message
{
public:
	enum Type { REQUEST = 1, RESPONSE = 2 };

	Vector!ubyte contents() const
	{
		Vector!ubyte send_buf = Vector!ubyte(3 + m_payload.length + 16);
		send_buf[0] = m_type;
		send_buf[1] = get_byte!ushort(0, m_payload.length);
		send_buf[2] = get_byte!ushort(1, m_payload.length);
		copy_mem(&send_buf[3], &m_payload[0], m_payload.length);
		// leave padding as all zeros
		
		return send_buf;
	}

	const Vector!ubyte payload() const { return m_payload; }

	bool is_request() const { return m_type == REQUEST; }

	this(in Vector!ubyte buf)
	{
		TLS_Data_Reader reader = TLS_Data_Reader("Heartbeat", buf);
		
		const ubyte type = reader.get_byte();
		
		if (type != 1 && type != 2)
			throw new TLS_Exception(Alert.ILLEGAL_PARAMETER,
			                        "Unknown heartbeat message type");
		
		m_type = cast(Type)(type);
		
		m_payload = reader.get_range!ubyte(2, 0, 16*1024);
		
		// padding follows and is ignored
	}

	this(Type type,
	     in ubyte* payload,
	     size_t payload_len) 
	{
		m_type = type;
		m_payload = Vector!ubyte(payload, payload + payload_len);
	}
private:
	Type m_type;
	Vector!ubyte m_payload;
};