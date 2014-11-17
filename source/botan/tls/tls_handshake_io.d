/*
* TLS Handshake Serialization
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_handshake_io;

import botan.tls.tls_magic;
import botan.tls.tls_version;
import botan.utils.loadstor;
import botan.tls.tls_messages;
import botan.tls.tls_record;
import botan.tls.tls_seq_numbers;
import botan.utils.exceptn;
import std.algorithm : count;
import functional;
import botan.utils.types;
import botan.utils.hashmap;
import std.typecons : Tuple;

/**
* Handshake IO Interface
*/
class Handshake_IO
{
public:
	abstract Protocol_Version initial_record_version() const;

	abstract Vector!ubyte send(in Handshake_Message msg);

	abstract Vector!ubyte format(in Vector!ubyte handshake_msg,
	                             Handshake_Type handshake_type) const;

	abstract void add_record(in Vector!ubyte record,
	                         Record_Type type,
	                         ulong sequence_number);

	/**
	* Returns (HANDSHAKE_NONE, Vector!(  )()) if no message currently available
	*/
	abstract Pair!(Handshake_Type, Vector!ubyte ) get_next_record(bool expecting_ccs);

	this() {}

	~this() {}
}

/**
* Handshake IO for stream-based handshakes
*/
package final class Stream_Handshake_IO : Handshake_IO
{
public:
	this(void delegate(ubyte, in Vector!ubyte) writer) 
	{
		m_send_hs = writer;
	}

	override Protocol_Version initial_record_version() const
	{
		return Protocol_Version.TLS_V10;
	}

	override Vector!ubyte send(in Handshake_Message msg)
	{
		const Vector!ubyte msg_bits = msg.serialize();
		
		if (msg.type() == HANDSHAKE_CCS)
		{
			m_send_hs(CHANGE_CIPHER_SPEC, msg_bits);
			return Vector!ubyte(); // not included in handshake hashes
		}
		
		const Vector!ubyte buf = format(msg_bits, msg.type());
		m_send_hs(HANDSHAKE, buf);
		return buf;
	}

	override Vector!ubyte format(in Vector!ubyte msg, Handshake_Type type) const
	{
		Vector!ubyte send_buf = Vector!ubyte(4 + msg.length);
		
		const size_t buf_size = msg.length;
		
		send_buf[0] = type;
		
		store_be24(&send_buf[1], buf_size);
		
		copy_mem(&send_buf[4], msg.ptr, msg.length);
		
		return send_buf;
	}

	override void add_record(in Vector!ubyte record, Record_Type record_type, ulong)
	{
		if (record_type == HANDSHAKE)
		{
			m_queue.insert(record);
		}
		else if (record_type == CHANGE_CIPHER_SPEC)
		{
			if (record.length != 1 || record[0] != 1)
				throw new Decoding_Error("Invalid ChangeCipherSpec");
			
			// Pretend it's a regular handshake message of zero length
			const(ubyte)[] ccs_hs = [ HANDSHAKE_CCS, 0, 0, 0 ];
			m_queue.insert(ccs_hs);
		}
		else
			throw new Decoding_Error("Unknown message type in handshake processing");
	}

	override Pair!(Handshake_Type, Vector!ubyte ) get_next_record(bool)
	{
		if (m_queue.length >= 4)
		{
			const size_t length = make_uint(0, m_queue[1], m_queue[2], m_queue[3]);
			
			if (m_queue.length >= length + 4)
			{
				Handshake_Type type = cast(Handshake_Type)(m_queue[0]);
				
				Vector!ubyte contents = Vector!ubyte(m_queue.ptr[4 .. 4 + length]);
				
				m_queue.remove(m_queue[0 .. 4 + length]);
				
				return Pair(type, contents);
			}
		}

		return Pair(HANDSHAKE_NONE, Vector!ubyte());
	}

private:
	Vector!ubyte m_queue;
	void delegate(ubyte, in Vector!ubyte) m_send_hs;
}

/**
* Handshake IO for datagram-based handshakes
*/
package final class Datagram_Handshake_IO : Handshake_IO
{
public:
	this(Connection_Sequence_Numbers seq, void delegate(ushort, ubyte, in Vector!ubyte) writer) 
	{
		m_seqs = seq;
		m_flights.length = 1;
		m_send_hs = writer; 
	}

	override Protocol_Version initial_record_version() const
	{
		return Protocol_Version.DTLS_V10;
	}

	override Vector!ubyte send(in Handshake_Message msg)
	{
		const Vector!ubyte msg_bits = msg.serialize();
		const ushort epoch = m_seqs.current_write_epoch();
		const Handshake_Type msg_type = msg.type();
		
		Tuple!(ushort, ubyte, Vector!ubyte) msg_info = Tuple!(ushort, ubyte, Vector!ubyte)(epoch, msg_type, msg_bits);
		
		if (msg_type == HANDSHAKE_CCS)
		{
			m_send_hs(epoch, CHANGE_CIPHER_SPEC, msg_bits);
			return Vector!ubyte(); // not included in handshake hashes
		}
		
		const Vector!ubyte no_fragment = format_w_seq(msg_bits, msg_type, m_out_message_seq);
		
		if (no_fragment.length + DTLS_HEADER_SIZE <= m_mtu)
			m_send_hs(epoch, HANDSHAKE, no_fragment);
		else
		{
			const size_t parts = split_for_mtu(m_mtu, msg_bits.length);
			
			const size_t parts_size = (msg_bits.length + parts) / parts;
			
			size_t frag_offset = 0;
			
			while (frag_offset != msg_bits.length)
			{
				const size_t frag_len =	std.algorithm.min(msg_bits.length - frag_offset, parts_size);
				
				m_send_hs(epoch, HANDSHAKE, 
				          format_fragment(&msg_bits[frag_offset],
											frag_len,
											frag_offset,
											msg_bits.length,
											msg_type,
											m_out_message_seq));
				
				frag_offset += frag_len;
			}
		}
		
		// Note: not saving CCS, instead we know it was there due to change in epoch
		m_flights[$-1].push_back(m_out_message_seq);
		m_flight_data[m_out_message_seq] = msg_info;
		
		m_out_message_seq += 1;
		
		return no_fragment;
	}

	override Vector!ubyte format(in Vector!ubyte msg, Handshake_Type type) const
	{
		return format_w_seq(msg, type, m_in_message_seq - 1);
	}

	override void add_record(in Vector!ubyte record,
	                         Record_Type record_type,
	                         ulong record_sequence)
	{
		const ushort epoch = cast(ushort)(record_sequence >> 48);
		
		if (record_type == CHANGE_CIPHER_SPEC)
		{
			if (!m_ccs_epochs.canFind(epoch))
				m_ccs_epochs ~= epoch;
			return;
		}
		
		__gshared immutable size_t DTLS_HANDSHAKE_HEADER_LEN = 12;
		
		const ubyte* record_bits = record.ptr;
		size_t record_size = record.length;
		
		while (record_size)
		{
			if (record_size < DTLS_HANDSHAKE_HEADER_LEN)
				return; // completely bogus? at least degenerate/weird
			
			const ubyte msg_type = record_bits[0];
			const size_t msg_len = load_be24(&record_bits[1]);
			const ushort message_seq = load_be!ushort(&record_bits[4], 0);
			const size_t fragment_offset = load_be24(&record_bits[6]);
			const size_t fragment_length = load_be24(&record_bits[9]);
			
			const size_t total_size = DTLS_HANDSHAKE_HEADER_LEN + fragment_length;
			
			if (record_size < total_size)
				throw new Decoding_Error("Bad lengths in DTLS header");
			
			if (message_seq >= m_in_message_seq)
			{
				m_messages[message_seq].add_fragment(&record_bits[DTLS_HANDSHAKE_HEADER_LEN],
														fragment_length,
														fragment_offset,
														epoch,
														msg_type,
														msg_len);
			}
			
			record_bits += total_size;
			record_size -= total_size;
		}
	}

	override Pair!(Handshake_Type, Vector!ubyte) get_next_record(bool expecting_ccs)
	{
		if (!m_flights[$-1].empty)
			m_flights.push_back(Vector!ushort());
		
		if (expecting_ccs)
		{
			if (!m_messages.empty)
			{
				const ushort current_epoch = m_messages.ptr.second.epoch();

				if (m_ccs_epochs.canFind(current_epoch))
					return Pair(HANDSHAKE_CCS, Vector!ubyte());
			}
			
			return Pair(HANDSHAKE_NONE, Vector!ubyte());
		}
		
		auto i = m_messages.find(m_in_message_seq);
		
		if (i == m_messages.end() || !i.second.complete())
			return Pair(HANDSHAKE_NONE, Vector!ubyte());
		
		m_in_message_seq += 1;
		
		return i.second.message();
	}

private:

Vector!ubyte format_fragment(in ubyte* fragment,
                             size_t frag_len,
                             ushort frag_offset,
                             ushort msg_len,
                             Handshake_Type type,
                             ushort msg_sequence) const
{
	Vector!ubyte send_buf = Vector!ubyte(12 + frag_len);
	
	send_buf[0] = type;
	
	store_be24(&send_buf[1], msg_len);
	
	store_be(msg_sequence, &send_buf[4]);
	
	store_be24(&send_buf[6], frag_offset);
	store_be24(&send_buf[9], frag_len);
	
	copy_mem(&send_buf[12], fragment.ptr, frag_len);
	
	return send_buf;
}

Vector!ubyte format_w_seq(in Vector!ubyte msg,
	             Handshake_Type type,
	             ushort msg_sequence) const
{
	return format_fragment(msg.ptr, msg.length, 0, msg.length, type, msg_sequence);
}

class Handshake_Reassembly
{
public:
	void add_fragment(in ubyte* fragment,
						size_t fragment_length,
						size_t fragment_offset,
						ushort epoch,
						ubyte msg_type,
						size_t msg_length)
	{
		if (complete())
			return; // already have entire message, ignore this
		
		if (m_msg_type == HANDSHAKE_NONE)
		{
			m_epoch = epoch;
			m_msg_type = msg_type;
			m_msg_length = msg_length;
		}
		
		if (msg_type != m_msg_type || msg_length != m_msg_length || epoch != m_epoch)
			throw new Decoding_Error("Inconsistent values in DTLS handshake header");
		
		if (fragment_offset > m_msg_length)
			throw new Decoding_Error("Fragment offset past end of message");
		
		if (fragment_offset + fragment_length > m_msg_length)
			throw new Decoding_Error("Fragment overlaps past end of message");
		
		if (fragment_offset == 0 && fragment_length == m_msg_length)
		{
			m_fragments.clear();
			m_message.replace(fragment[0 .. fragment+fragment_length]);
		}
		else
		{
			/*
			* FIXME. This is a pretty lame way to do defragmentation, huge
			* overhead with a tree node per ubyte.
			*
			* Also should confirm that all overlaps have no changes,
			* otherwise we expose ourselves to the classic fingerprinting
			* and IDS evasion attacks on IP fragmentation.
			*/
			foreach (size_t i; 0 .. fragment_length)
				m_fragments[fragment_offset+i] = fragment[i];
			
			if (m_fragments.length == m_msg_length)
			{
				m_message.resize(m_msg_length);
				foreach (size_t i; 0 .. m_msg_length)
					m_message[i] = m_fragments[i];
				m_fragments.clear();
			}
		}
	}

	bool complete() const
	{
		return (m_msg_type != HANDSHAKE_NONE && m_message.length == m_msg_length);
	}

	ushort epoch() const { return m_epoch; }

	Pair!(Handshake_Type, Vector!ubyte) message() const
	{
		if (!complete())
			throw new Internal_Error("Datagram_Handshake_IO - message not complete");
		
		return Pair(cast(Handshake_Type)(m_msg_type), m_message);
	}

	private:
		ubyte m_msg_type = HANDSHAKE_NONE;
		size_t m_msg_length = 0;
		ushort m_epoch = 0;

		HashMap!(size_t, ubyte) m_fragments;
		Vector!ubyte m_message;
	}

	Connection_Sequence_Numbers m_seqs;
	HashMap!(ushort, Handshake_Reassembly) m_messages;
	ushort[] m_ccs_epochs;
	Vector!( Vector!ushort ) m_flights;
	HashMap!(ushort, Tuple!(ushort, ubyte, Vector!ubyte) ) m_flight_data;

	// default MTU is IPv6 min MTU minus UDP/IP headers
	ushort m_mtu = 1280 - 40 - 8;
	ushort m_in_message_seq = 0;
	ushort m_out_message_seq = 0;
	void delegate(ushort, ubyte, in Vector!ubyte) m_send_hs;
}


private:

size_t load_be24(const ubyte q[3])
{
	return make_uint(0,
	                 q[0],
					q[1],
					q[2]);
}

void store_be24(ubyte[3] output, size_t val)
{
	output[0] = get_byte!uint(1, val);
	output[1] = get_byte!uint(2, val);
	output[2] = get_byte!uint(3, val);
}

size_t split_for_mtu(size_t mtu, size_t msg_size)
{
	__gshared immutable size_t DTLS_HEADERS_SIZE = 25; // DTLS record+handshake headers
	
	const size_t parts = (msg_size + mtu) / mtu;
	
	if (parts + DTLS_HEADERS_SIZE > mtu)
		return parts + 1;
	
	return parts;
}
