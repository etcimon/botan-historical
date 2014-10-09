/*
* TLS Handshake Serialization
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.tls_magic;
import botan.tls_version;
import botan.loadstor;
import functional;
import vector;
import deque;
import map;
import set;
import utility;
import tuple;
namespace TLS {

class Handshake_Message;

/**
* Handshake IO Interface
*/
class Handshake_IO
{
public:
	abstract Protocol_Version initial_record_version() const;

	abstract Vector!ubyte send(in Handshake_Message msg);

	abstract Vector!ubyte format(
		in Vector!ubyte handshake_msg,
		Handshake_Type handshake_type) const;

	abstract void add_record(in Vector!ubyte record,
									Record_Type type,
									ulong sequence_number);

	/**
	* Returns (HANDSHAKE_NONE, Vector!(  )()) if no message currently available
	*/
	abstract Pair!(Handshake_Type, Vector!( ubyte) )
		get_next_record(bool expecting_ccs);

	Handshake_IO() {}

	Handshake_IO(in Handshake_IO);

	Handshake_IO& operator=(in Handshake_IO);

	~this() {}
};

/**
* Handshake IO for stream-based handshakes
*/
class Stream_Handshake_IO : Handshake_IO
{
public:
	Stream_Handshake_IO(void delegate(ubyte, in Vector!ubyte) writer) :
		m_send_hs(writer) {}

	override Protocol_Version initial_record_version() const;

	override Vector!ubyte send(in Handshake_Message msg);

	override Vector!ubyte format(
		in Vector!ubyte handshake_msg,
		 Handshake_Type handshake_type) const;

	override void add_record(in Vector!ubyte record,
						 Record_Type type,
						  ulong sequence_number);

	override Pair!(Handshake_Type, Vector!( ubyte) )
		 get_next_record(bool expecting_ccs);
private:
	std::deque<ubyte> m_queue;
	void delegate(ubyte, in Vector!ubyte) m_send_hs;
};

/**
* Handshake IO for datagram-based handshakes
*/
class Datagram_Handshake_IO : Handshake_IO
{
public:
	Datagram_Handshake_IO(class Connection_Sequence_Numbers& seq,
								 void delegate(ushort, ubyte, in Vector!ubyte) writer) :
		m_seqs(seq), m_flights(1), m_send_hs(writer) {}

	override Protocol_Version initial_record_version() const;

	override Vector!ubyte send(in Handshake_Message msg);

	override Vector!ubyte format(
		in Vector!ubyte handshake_msg,
		 Handshake_Type handshake_type) const;

	override void add_record(in Vector!ubyte record,
						 Record_Type type,
						  ulong sequence_number);

	override Pair!(Handshake_Type, Vector!( ubyte) )
		get_next_record(bool expecting_ccs);
private:
	Vector!ubyte format_fragment(
		in ubyte* fragment,
		size_t fragment_len,
		ushort frag_offset,
		ushort msg_len,
		Handshake_Type type,
		ushort msg_sequence) const;

	Vector!ubyte format_w_seq(
		in Vector!ubyte handshake_msg,
		Handshake_Type handshake_type,
		ushort msg_sequence) const;

	class Handshake_Reassembly
	{
		public:
			void add_fragment(in ubyte* fragment,
									size_t fragment_length,
									size_t fragment_offset,
									ushort epoch,
									ubyte msg_type,
									size_t msg_length);

			bool complete() const;

			ushort epoch() const { return m_epoch; }

			Pair!(Handshake_Type, Vector!( ubyte) ) message() const;
		private:
			ubyte m_msg_type = HANDSHAKE_NONE;
			size_t m_msg_length = 0;
			ushort m_epoch = 0;

			HashMap<size_t, ubyte> m_fragments;
			Vector!ubyte m_message;
	};

	class Connection_Sequence_Numbers& m_seqs;
	HashMap<ushort, Handshake_Reassembly> m_messages;
	Set<ushort> m_ccs_epochs;
	Vector!( std::vector<ushort )> m_flights;
	HashMap<ushort, std::tuple<ushort, ubyte, Vector!ubyte>> m_flight_data;

	// default MTU is IPv6 min MTU minus UDP/IP headers
	ushort m_mtu = 1280 - 40 - 8;
	ushort m_in_message_seq = 0;
	ushort m_out_message_seq = 0;
	void delegate(ushort, ubyte, in Vector!ubyte) m_send_hs;
};

}