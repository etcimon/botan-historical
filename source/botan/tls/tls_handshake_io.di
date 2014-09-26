/*
* TLS Handshake Serialization
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

#include <botan/tls_magic.h>
#include <botan/tls_version.h>
#include <botan/loadstor.h>
#include <functional>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <utility>
#include <tuple>
namespace TLS {

class Handshake_Message;

/**
* Handshake IO Interface
*/
class Handshake_IO
{
	public:
		abstract Protocol_Version initial_record_version() const;

		abstract Vector!( byte ) send(in Handshake_Message msg);

		abstract Vector!( byte ) format(
			in Vector!byte handshake_msg,
			Handshake_Type handshake_type) const;

		abstract void add_record(in Vector!byte record,
										Record_Type type,
										ulong sequence_number);

		/**
		* Returns (HANDSHAKE_NONE, Vector!(  )()) if no message currently available
		*/
		abstract Pair!(Handshake_Type, Vector!( byte) )
			get_next_record(bool expecting_ccs);

		Handshake_IO() {}

		Handshake_IO(in Handshake_IO);

		Handshake_IO& operator=(in Handshake_IO);

		abstract ~Handshake_IO() {}
};

/**
* Handshake IO for stream-based handshakes
*/
class Stream_Handshake_IO : public Handshake_IO
{
	public:
		Stream_Handshake_IO(void delegate(byte, in Vector!byte) writer) :
			m_send_hs(writer) {}

		Protocol_Version initial_record_version() const override;

		Vector!( byte ) send(in Handshake_Message msg) override;

		Vector!( byte ) format(
			in Vector!byte handshake_msg,
			Handshake_Type handshake_type) const override;

		void add_record(in Vector!byte record,
							 Record_Type type,
							 ulong sequence_number) override;

		Pair!(Handshake_Type, Vector!( byte) )
			get_next_record(bool expecting_ccs) override;
	private:
		std::deque<byte> m_queue;
		void delegate(byte, in Vector!byte) m_send_hs;
};

/**
* Handshake IO for datagram-based handshakes
*/
class Datagram_Handshake_IO : public Handshake_IO
{
	public:
		Datagram_Handshake_IO(class Connection_Sequence_Numbers& seq,
									 void delegate(ushort, byte, in Vector!byte) writer) :
			m_seqs(seq), m_flights(1), m_send_hs(writer) {}

		Protocol_Version initial_record_version() const override;

		Vector!( byte ) send(in Handshake_Message msg) override;

		Vector!( byte ) format(
			in Vector!byte handshake_msg,
			Handshake_Type handshake_type) const override;

		void add_record(in Vector!byte record,
							 Record_Type type,
							 ulong sequence_number) override;

		Pair!(Handshake_Type, Vector!( byte) )
			get_next_record(bool expecting_ccs) override;
	private:
		Vector!( byte ) format_fragment(
			in byte* fragment,
			size_t fragment_len,
			ushort frag_offset,
			ushort msg_len,
			Handshake_Type type,
			ushort msg_sequence) const;

		Vector!( byte ) format_w_seq(
			in Vector!byte handshake_msg,
			Handshake_Type handshake_type,
			ushort msg_sequence) const;

		class Handshake_Reassembly
		{
			public:
				void add_fragment(in byte* fragment,
										size_t fragment_length,
										size_t fragment_offset,
										ushort epoch,
										byte msg_type,
										size_t msg_length);

				bool complete() const;

				ushort epoch() const { return m_epoch; }

				Pair!(Handshake_Type, Vector!( byte) ) message() const;
			private:
				byte m_msg_type = HANDSHAKE_NONE;
				size_t m_msg_length = 0;
				ushort m_epoch = 0;

				std::map<size_t, byte> m_fragments;
				Vector!( byte ) m_message;
		};

		class Connection_Sequence_Numbers& m_seqs;
		std::map<ushort, Handshake_Reassembly> m_messages;
		std::set<ushort> m_ccs_epochs;
		Vector!( std::vector<ushort )> m_flights;
		std::map<ushort, std::tuple<ushort, byte, Vector!( byte )>> m_flight_data;

		// default MTU is IPv6 min MTU minus UDP/IP headers
		ushort m_mtu = 1280 - 40 - 8;
		ushort m_in_message_seq = 0;
		ushort m_out_message_seq = 0;
		void delegate(ushort, byte, in Vector!byte) m_send_hs;
};

}