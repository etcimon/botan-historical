/*
* TLS Heartbeats
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.heartbeats;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.utils.memory.zeroize;
import botan.tls.extensions;
import botan.tls.reader;
import botan.tls.exceptn;
import botan.utils.types;

/**
* TLS Heartbeat message
*/
struct HeartbeatMessage
{
public:
    alias ubyte MessageType;
    enum MessageType { REQUEST = 1, RESPONSE = 2 }

    Vector!ubyte contents() const
    {
        Vector!ubyte send_buf = Vector!ubyte(3 + m_payload.length + 16);
        send_buf[0] = m_type;
        send_buf[1] = get_byte!ushort(0, m_payload.length);
        send_buf[2] = get_byte!ushort(1, m_payload.length);
        copyMem(&send_buf[3], m_payload.ptr, m_payload.length);
        // leave padding as all zeros
        
        return send_buf;
    }

    Vector!ubyte payload() const { return m_payload; }

    bool isRequest() const { return m_type == REQUEST; }

    this(in Vector!ubyte buf)
    {
        TLSDataReader reader = TLSDataReader("Heartbeat", buf);
        
        const ubyte type = reader.get_byte();
        
        if (type != 1 && type != 2)
            throw new TLSException(TLSAlert.ILLEGAL_PARAMETER,
                                    "Unknown heartbeat message type");
        
        m_type = cast(MessageType)(type);
        
        m_payload = reader.getRange!ubyte(2, 0, 16*1024);
        
        // padding follows and is ignored
    }

    this(MessageType type,
         in ubyte* payload,
         size_t payload_len) 
    {
        m_type = type;
        m_payload = Vector!ubyte(payload, payload + payload_len);
    }
private:
    MessageType m_type;
    Vector!ubyte m_payload;
}