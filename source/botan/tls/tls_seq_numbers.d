/*
* TLS Sequence Number Handling
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_seq_numbers;

import botan.utils.types;
import stdexcept;


class Connection_Sequence_Numbers
{
public:
	abstract void new_read_cipher_state();
	abstract void new_write_cipher_state();

	abstract ushort current_read_epoch() const;
	abstract ushort current_write_epoch() const;

	abstract ulong next_write_sequence();
	abstract ulong next_read_sequence();

	abstract bool already_seen(ulong seq) const;
	abstract void read_accept(ulong seq);
};

final class Stream_Sequence_Numbers : Connection_Sequence_Numbers
{
public:
	override void new_read_cipher_state() { m_read_seq_no = 0; m_read_epoch += 1; }
	override void new_write_cipher_state() { m_write_seq_no = 0; m_write_epoch += 1; }

	override ushort current_read_epoch() const { return m_read_epoch; }
	override ushort current_write_epoch() const { return m_write_epoch; }

	override ulong next_write_sequence() { return m_write_seq_no++; }
	override ulong next_read_sequence() { return m_read_seq_no; }

	override bool already_seen(ulong) const { return false; }
	override void read_accept(ulong) { m_read_seq_no++; }
private:
	ulong m_write_seq_no = 0;
	ulong m_read_seq_no = 0;
	ushort m_read_epoch = 0;
	ushort m_write_epoch = 0;
};

final class Datagram_Sequence_Numbers : Connection_Sequence_Numbers
{
public:
	override void new_read_cipher_state() { m_read_epoch += 1; }

	override void new_write_cipher_state()
	{
		// increment epoch
		m_write_seq_no = ((m_write_seq_no >> 48) + 1) << 48;
	}

	override ushort current_read_epoch() const { return m_read_epoch; }
	override ushort current_write_epoch() const { return (m_write_seq_no >> 48); }

	override ulong next_write_sequence() { return m_write_seq_no++; }

	override ulong next_read_sequence()
	{
		throw new Exception("DTLS uses explicit sequence numbers");
	}

	override bool already_seen(ulong sequence) const
	{
		const size_t window_size = (m_window_bits).sizeof * 8;

		if (sequence > m_window_highest)
			return false;

		const ulong offset = m_window_highest - sequence;

		if (offset >= window_size)
			return true; // really old?

		return (((m_window_bits >> offset) & 1) == 1);
	}

	override void read_accept(ulong sequence)
	{
		const size_t window_size = (m_window_bits).sizeof * 8;

		if (sequence > m_window_highest)
		{
			const size_t offset = sequence - m_window_highest;
			m_window_highest += offset;

			if (offset >= window_size)
				m_window_bits = 0;
			else
				m_window_bits <<= offset;

			m_window_bits |= 0x01;
		}
		else
		{
			const ulong offset = m_window_highest - sequence;
			m_window_bits |= (cast(ulong)(1) << offset);
		}
	}

private:
	ulong m_write_seq_no = 0;
	ushort m_read_epoch = 0;
	ulong m_window_highest = 0;
	ulong m_window_bits = 0;
};