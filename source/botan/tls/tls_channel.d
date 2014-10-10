/*
* TLS Channels
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.tls_channel;
import botan.internal.tls_handshake_state;
import botan.internal.tls_messages;
import botan.internal.tls_heartbeats;
import botan.internal.tls_record;
import botan.internal.tls_seq_numbers;
import botan.utils.rounding;
import botan.internal.stl_util;
import botan.loadstor;
namespace TLS {

Channel::Channel(void delegate(in ubyte[]) output_fn,
					  void delegate(in ubyte[]) data_cb,
					  void delegate(Alert, in ubyte[]) alert_cb,
					  bool delegate(in Session) handshake_cb,
					  Session_Manager session_manager,
					  RandomNumberGenerator rng,
					  size_t reserved_io_buffer_size) :
	m_handshake_cb(handshake_cb),
	m_data_cb(data_cb),
	m_alert_cb(alert_cb),
	m_output_fn(output_fn),
	m_rng(rng),
	m_session_manager(session_manager)
{
	/* epoch 0 is plaintext, thus null cipher state */
	m_write_cipher_states[0] = null;
	m_read_cipher_states[0] = null;

	m_writebuf.reserve(reserved_io_buffer_size);
	m_readbuf.reserve(reserved_io_buffer_size);
}

void Channel::reset_state()
{
	m_active_state.reset();
	m_pending_state.reset();
	m_readbuf.clear();
	m_write_cipher_states.clear();
	m_read_cipher_states.clear();
}

Channel::~this()
{
	// So unique_ptr destructors run correctly
}

Connection_Sequence_Numbers& Channel::sequence_numbers() const
{
	BOTAN_ASSERT(m_sequence_numbers, "Have a sequence numbers object");
	return *m_sequence_numbers;
}

std::shared_ptr<Connection_Cipher_State> Channel::read_cipher_state_epoch(ushort epoch) const
{
	auto i = m_read_cipher_states.find(epoch);

	BOTAN_ASSERT(i != m_read_cipher_states.end(),
					 "Have a cipher state for the specified epoch");

	return i.second;
}

std::shared_ptr<Connection_Cipher_State> Channel::write_cipher_state_epoch(ushort epoch) const
{
	auto i = m_write_cipher_states.find(epoch);

	BOTAN_ASSERT(i != m_write_cipher_states.end(),
					 "Have a cipher state for the specified epoch");

	return i.second;
}

Vector!( X509_Certificate ) Channel::peer_cert_chain() const
{
	if (auto active = active_state())
		return get_peer_cert_chain(*active);
	return Vector!( X509_Certificate )();
}

Handshake_State& Channel::create_handshake_state(Protocol_Version _version)
{
	if (pending_state())
		throw new Internal_Error("create_handshake_state called during handshake");

	if (auto active = active_state())
	{
		Protocol_Version active_version = active._version();

		if (active_version.is_datagram_protocol() != _version.is_datagram_protocol())
			throw new Exception("Active state using version " ~
											 active_version.to_string() +
											 " cannot change to " ~
											 _version.to_string() +
											 " in pending");
	}

	if (!m_sequence_numbers)
	{
		if (_version.is_datagram_protocol())
			m_sequence_numbers.reset(new Datagram_Sequence_Numbers);
		else
			m_sequence_numbers.reset(new Stream_Sequence_Numbers);
	}

	Unique!Handshake_IO io;
	if (_version.is_datagram_protocol())
		io.reset(new Datagram_Handshake_IO(
						sequence_numbers(),
						std::bind(&Channel::send_record_under_epoch, this,
									 std::placeholders::_1,
									 std::placeholders::_2,
									 std::placeholders::_3)));
	else
		io.reset(new Stream_Handshake_IO(
						std::bind(&Channel::send_record, this,
									 std::placeholders::_1,
									 std::placeholders::_2)));

	m_pending_state.reset(new_handshake_state(io.release()));

	if (auto active = active_state())
		m_pending_state.set_version(active._version());

	return *m_pending_state.get();
}

void Channel::renegotiate(bool force_full_renegotiation)
{
	if (pending_state()) // currently in handshake?
		return;

	if (auto active = active_state())
		initiate_handshake(create_handshake_state(active._version()),
								 force_full_renegotiation);
	else
		throw new Exception("Cannot renegotiate on inactive connection");
}

size_t Channel::maximum_fragment_size() const
{
	// should we be caching this value?

	if (auto pending = pending_state())
		if (auto server_hello = pending.server_hello())
			if (size_t frag = server_hello.fragment_size())
				return frag;

	if (auto active = active_state())
		if (size_t frag = active.server_hello().fragment_size())
			return frag;

	return MAX_PLAINTEXT_SIZE;
}

void Channel::change_cipher_spec_reader(Connection_Side side)
{
	auto pending = pending_state();

	BOTAN_ASSERT(pending && pending.server_hello(),
					 "Have received server hello");

	if (pending.server_hello().compression_method() != NO_COMPRESSION)
		throw new Internal_Error("Negotiated unknown compression algorithm");

	sequence_numbers().new_read_cipher_state();

	const ushort epoch = sequence_numbers().current_read_epoch();

	BOTAN_ASSERT(m_read_cipher_states.count(epoch) == 0,
					 "No read cipher state currently set for next epoch");

	// flip side as we are reading
	std::shared_ptr<Connection_Cipher_State> read_state(
		new Connection_Cipher_State(pending._version(),
											 (side == CLIENT) ? SERVER : CLIENT,
											 false,
											 pending.ciphersuite(),
											 pending.session_keys()));

	m_read_cipher_states[epoch] = read_state;
}

void Channel::change_cipher_spec_writer(Connection_Side side)
{
	auto pending = pending_state();

	BOTAN_ASSERT(pending && pending.server_hello(),
					 "Have received server hello");

	if (pending.server_hello().compression_method() != NO_COMPRESSION)
		throw new Internal_Error("Negotiated unknown compression algorithm");

	sequence_numbers().new_write_cipher_state();

	const ushort epoch = sequence_numbers().current_write_epoch();

	BOTAN_ASSERT(m_write_cipher_states.count(epoch) == 0,
					 "No write cipher state currently set for next epoch");

	std::shared_ptr<Connection_Cipher_State> write_state(
		new Connection_Cipher_State(pending._version(),
											 side,
											 true,
											 pending.ciphersuite(),
											 pending.session_keys()));

	m_write_cipher_states[epoch] = write_state;
}

bool Channel::is_active() const
{
	return (active_state() != null);
}

bool Channel::is_closed() const
{
	if (active_state() || pending_state())
		return false;

	/*
	* If no active or pending state, then either we had a connection
	* and it has been closed, or we are a server which has never
	* received a connection. This case is detectable by also lacking
	* m_sequence_numbers
	*/
	return (m_sequence_numbers != null);
}

void Channel::activate_session()
{
	std.algorithm.swap(m_active_state, m_pending_state);
	m_pending_state.reset();

	if (m_active_state._version().is_datagram_protocol())
	{
		// FIXME, remove old states when we are sure not needed anymore
	}
	else
	{
		// TLS is easy just remove all but the current state
		auto current_epoch = sequence_numbers().current_write_epoch();

		const auto not_current_epoch =
			[current_epoch](ushort epoch) { return (epoch != current_epoch); };

		map_remove_if (not_current_epoch, m_write_cipher_states);
		map_remove_if (not_current_epoch, m_read_cipher_states);
	}
}

bool Channel::peer_supports_heartbeats() const
{
	if (auto active = active_state())
		return active.server_hello().supports_heartbeats();
	return false;
}

bool Channel::heartbeat_sending_allowed() const
{
	if (auto active = active_state())
		return active.server_hello().peer_can_send_heartbeats();
	return false;
}

size_t Channel::received_data(in Vector!ubyte buf)
{
	return this.received_data(&buf[0], buf.size());
}

size_t Channel::received_data(in ubyte* input, size_t input_size)
{
	const auto get_cipherstate = [this](ushort epoch)
	{ return this.read_cipher_state_epoch(epoch).get(); };

	const size_t max_fragment_size = maximum_fragment_size();

	try
	{
		while(!is_closed() && input_size)
		{
			SafeVector!ubyte record;
			ulong record_sequence = 0;
			Record_Type record_type = NO_RECORD;
			Protocol_Version record_version;

			size_t consumed = 0;

			const size_t needed =
				read_record(m_readbuf,
								input,
								input_size,
								consumed,
								record,
								&record_sequence,
								&record_version,
								&record_type,
								m_sequence_numbers.get(),
								get_cipherstate);

			BOTAN_ASSERT(consumed <= input_size,
							 "Record reader consumed sane amount");

			input += consumed;
			input_size -= consumed;

			BOTAN_ASSERT(input_size == 0 || needed == 0,
							 "Got a full record or consumed all input");

			if (input_size == 0 && needed != 0)
				return needed; // need more data to complete record

			if (record.size() > max_fragment_size)
				throw new TLS_Exception(Alert::RECORD_OVERFLOW,
										  "Plaintext record is too large");

			if (record_type == HANDSHAKE || record_type == CHANGE_CIPHER_SPEC)
			{
				if (!m_pending_state)
				{
					create_handshake_state(record_version);
					if (record_version.is_datagram_protocol())
						sequence_numbers().read_accept(record_sequence);
				}

				m_pending_state.handshake_io().add_record(unlock(record),
																		 record_type,
																		 record_sequence);

				while(auto pending = m_pending_state.get())
				{
					auto msg = pending.get_next_handshake_msg();

					if (msg.first == HANDSHAKE_NONE) // no full handshake yet
						break;

					process_handshake_msg(active_state(), *pending,
												 msg.first, msg.second);
				}
			}
			else if (record_type == HEARTBEAT && peer_supports_heartbeats())
			{
				if (!active_state())
					throw new Unexpected_Message("Heartbeat sent before handshake done");

				Heartbeat_Message heartbeat(unlock(record));

				in Vector!ubyte payload = heartbeat.payload();

				if (heartbeat.is_request())
				{
					if (!pending_state())
					{
						Heartbeat_Message response(Heartbeat_Message::RESPONSE,
															&payload[0], payload.size());

						send_record(HEARTBEAT, response.contents());
					}
				}
				else
				{
					m_alert_cb(Alert(Alert::HEARTBEAT_PAYLOAD), &payload[0], payload.size());
				}
			}
			else if (record_type == APPLICATION_DATA)
			{
				if (!active_state())
					throw new Unexpected_Message("Application data before handshake done");

				/*
				* OpenSSL among others sends empty records in versions
				* before TLS v1.1 in order to randomize the IV of the
				* following record. Avoid spurious callbacks.
				*/
				if (record.size() > 0)
					m_data_cb(&record[0], record.size());
			}
			else if (record_type == ALERT)
			{
				Alert alert_msg(record);

				if (alert_msg.type() == Alert::NO_RENEGOTIATION)
					m_pending_state.reset();

				m_alert_cb(alert_msg, null, 0);

				if (alert_msg.is_fatal())
				{
					if (auto active = active_state())
						m_session_manager.remove_entry(active.server_hello().session_id());
				}

				if (alert_msg.type() == Alert::CLOSE_NOTIFY)
					send_warning_alert(Alert::CLOSE_NOTIFY); // reply in kind

				if (alert_msg.type() == Alert::CLOSE_NOTIFY || alert_msg.is_fatal())
				{
					reset_state();
					return 0;
				}
			}
			else
				throw new Unexpected_Message("Unexpected record type " ~
												 std.conv.to!string(record_type) +
												 " from counterparty");
		}

		return 0; // on a record boundary
	}
	catch(TLS_Exception& e)
	{
		send_fatal_alert(e.type());
		throw;
	}
	catch(Integrity_Failure& e)
	{
		send_fatal_alert(Alert::BAD_RECORD_MAC);
		throw;
	}
	catch(Decoding_Error e)
	{
		send_fatal_alert(Alert::DECODE_ERROR);
		throw;
	}
	catch
	{
		send_fatal_alert(Alert::INTERNAL_ERROR);
		throw;
	}
}

void Channel::heartbeat(in ubyte* payload, size_t payload_size)
{
	if (heartbeat_sending_allowed())
	{
		Heartbeat_Message heartbeat(Heartbeat_Message::REQUEST,
											 payload, payload_size);

		send_record(HEARTBEAT, heartbeat.contents());
	}
}

void Channel::write_record(Connection_Cipher_State* cipher_state,
									ubyte record_type, in ubyte* input, size_t length)
{
	BOTAN_ASSERT(m_pending_state || m_active_state,
					 "Some connection state exists");

	Protocol_Version record_version =
		(m_pending_state) ? (m_pending_state._version()) : (m_active_state._version());

	TLS::write_record(m_writebuf,
							record_type,
							input,
							length,
							record_version,
							sequence_numbers().next_write_sequence(),
							cipher_state,
							m_rng);

	m_output_fn(&m_writebuf[0], m_writebuf.size());
}

void Channel::send_record_array(ushort epoch, ubyte type, in ubyte* input, size_t length)
{
	if (length == 0)
		return;

	/*
	* If using CBC mode without an explicit IV (SSL v3 or TLS v1.0),
	* send a single ubyte of plaintext to randomize the (implicit) IV of
	* the following main block. If using a stream cipher, or TLS v1.1
	* or higher, this isn't necessary.
	*
	* An empty record also works but apparently some implementations do
	* not like this (https://bugzilla.mozilla.org/show_bug.cgi?id=665814)
	*
	* See http://www.openssl.org/~bodo/tls-cbc.txt for background.
	*/

	auto cipher_state = write_cipher_state_epoch(epoch);

	if (type == APPLICATION_DATA && cipher_state.cbc_without_explicit_iv())
	{
		write_record(cipher_state.get(), type, &input[0], 1);
		input += 1;
		length -= 1;
	}

	const size_t max_fragment_size = maximum_fragment_size();

	while(length)
	{
		const size_t sending = std.algorithm.min(length, max_fragment_size);
		write_record(cipher_state.get(), type, &input[0], sending);

		input += sending;
		length -= sending;
	}
}

void Channel::send_record(ubyte record_type, in Vector!ubyte record)
{
	send_record_array(sequence_numbers().current_write_epoch(),
							record_type, &record[0], record.size());
}

void Channel::send_record_under_epoch(ushort epoch, ubyte record_type,
												  in Vector!ubyte record)
{
	send_record_array(epoch, record_type, &record[0], record.size());
}

void Channel::send(in ubyte* buf, size_t buf_size)
{
	if (!is_active())
		throw new Exception("Data cannot be sent on inactive TLS connection");

	send_record_array(sequence_numbers().current_write_epoch(),
							APPLICATION_DATA, buf, buf_size);
}

void Channel::send(in string string)
{
	this.send(cast(const ubyte*)(string.c_str()), string.size());
}

void Channel::send_alert(in Alert alert)
{
	if (alert.is_valid() && !is_closed())
	{
		try
		{
			send_record(ALERT, alert.serialize());
		}
		catch { /* swallow it */ }
	}

	if (alert.type() == Alert::NO_RENEGOTIATION)
		m_pending_state.reset();

	if (alert.is_fatal())
		if (auto active = active_state())
			m_session_manager.remove_entry(active.server_hello().session_id());

	if (alert.type() == Alert::CLOSE_NOTIFY || alert.is_fatal())
		reset_state();
}

void Channel::secure_renegotiation_check(const Client_Hello* client_hello)
{
	const bool secure_renegotiation = client_hello.secure_renegotiation();

	if (auto active = active_state())
	{
		const bool active_sr = active.client_hello().secure_renegotiation();

		if (active_sr != secure_renegotiation)
			throw new TLS_Exception(Alert::HANDSHAKE_FAILURE,
									  "Client changed its mind about secure renegotiation");
	}

	if (secure_renegotiation)
	{
		in Vector!ubyte data = client_hello.renegotiation_info();

		if (data != secure_renegotiation_data_for_client_hello())
			throw new TLS_Exception(Alert::HANDSHAKE_FAILURE,
									  "Client sent bad values for secure renegotiation");
	}
}

void Channel::secure_renegotiation_check(const Server_Hello* server_hello)
{
	const bool secure_renegotiation = server_hello.secure_renegotiation();

	if (auto active = active_state())
	{
		const bool active_sr = active.client_hello().secure_renegotiation();

		if (active_sr != secure_renegotiation)
			throw new TLS_Exception(Alert::HANDSHAKE_FAILURE,
									  "Server changed its mind about secure renegotiation");
	}

	if (secure_renegotiation)
	{
		in Vector!ubyte data = server_hello.renegotiation_info();

		if (data != secure_renegotiation_data_for_server_hello())
			throw new TLS_Exception(Alert::HANDSHAKE_FAILURE,
									  "Server sent bad values for secure renegotiation");
	}
}

Vector!ubyte Channel::secure_renegotiation_data_for_client_hello() const
{
	if (auto active = active_state())
		return active.client_finished().verify_data();
	return Vector!ubyte();
}

Vector!ubyte Channel::secure_renegotiation_data_for_server_hello() const
{
	if (auto active = active_state())
	{
		Vector!ubyte buf = active.client_finished().verify_data();
		buf += active.server_finished().verify_data();
		return buf;
	}

	return Vector!ubyte();
}

bool Channel::secure_renegotiation_supported() const
{
	if (auto active = active_state())
		return active.server_hello().secure_renegotiation();

	if (auto pending = pending_state())
		if (auto hello = pending.server_hello())
			return hello.secure_renegotiation();

	return false;
}

SymmetricKey Channel::key_material_export(in string label,
														in string context,
														size_t length) const
{
	if (auto active = active_state())
	{
		Unique!KDF prf = active.protocol_specific_prf();

		in SafeVector!ubyte master_secret =
			active.session_keys().master_secret();

		Vector!ubyte salt;
		salt += to_byte_vector(label);
		salt += active.client_hello().random();
		salt += active.server_hello().random();

		if (context != "")
		{
			size_t context_size = context.length;
			if (context_size > 0xFFFF)
				throw new Exception("key_material_export context is too long");
			salt.push_back(get_byte<ushort>(0, context_size));
			salt.push_back(get_byte<ushort>(1, context_size));
			salt += to_byte_vector(context);
		}

		return prf.derive_key(length, master_secret, salt);
	}
	else
		throw new Exception("Channel::key_material_export connection not active");
}

}

}

