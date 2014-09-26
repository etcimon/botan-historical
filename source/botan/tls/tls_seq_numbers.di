/*
* TLS Sequence Number Handling
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

#include <botan/types.h>
#include <stdexcept>
namespace TLS {

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

class Stream_Sequence_Numbers : public Connection_Sequence_Numbers
{
	public:
		void new_read_cipher_state() override { m_read_seq_no = 0; m_read_epoch += 1; }
		void new_write_cipher_state() override { m_write_seq_no = 0; m_write_epoch += 1; }

		ushort current_read_epoch() const override { return m_read_epoch; }
		ushort current_write_epoch() const override { return m_write_epoch; }

		ulong next_write_sequence() override { return m_write_seq_no++; }
		ulong next_read_sequence() override { return m_read_seq_no; }

		bool already_seen(ulong) const override { return false; }
		void read_accept(ulong) override { m_read_seq_no++; }
	private:
		ulong m_write_seq_no = 0;
		ulong m_read_seq_no = 0;
		ushort m_read_epoch = 0;
		ushort m_write_epoch = 0;
};

class Datagram_Sequence_Numbers : public Connection_Sequence_Numbers
{
	public:
		void new_read_cipher_state() override { m_read_epoch += 1; }

		void new_write_cipher_state() override
		{
			// increment epoch
			m_write_seq_no = ((m_write_seq_no >> 48) + 1) << 48;
		}

		ushort current_read_epoch() const override { return m_read_epoch; }
		ushort current_write_epoch() const override { return (m_write_seq_no >> 48); }

		ulong next_write_sequence() override { return m_write_seq_no++; }

		ulong next_read_sequence() override
		{
			throw new Exception("DTLS uses explicit sequence numbers");
		}

		bool already_seen(ulong sequence) const override
		{
			const size_t window_size = sizeof(m_window_bits) * 8;

			if(sequence > m_window_highest)
				return false;

			const ulong offset = m_window_highest - sequence;

			if(offset >= window_size)
				return true; // really old?

			return (((m_window_bits >> offset) & 1) == 1);
		}

		void read_accept(ulong sequence) override
		{
			const size_t window_size = sizeof(m_window_bits) * 8;

			if(sequence > m_window_highest)
			{
				const size_t offset = sequence - m_window_highest;
				m_window_highest += offset;

				if(offset >= window_size)
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

}