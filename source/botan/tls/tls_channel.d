/*
* TLS Channel
* (C) 2011,2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_channel;

import botan.constants;
static if (BOTAN_HAS_TLS):

public import botan.cert.x509.x509cert;
public import botan.tls.tls_policy;
public import botan.tls.tls_session;
public import botan.tls.tls_alert;
public import botan.tls.tls_session_manager;
public import botan.tls.tls_version;
public import botan.tls.tls_exceptn;
public import botan.rng.rng;
import botan.tls.tls_handshake_state;
import botan.tls.tls_messages;
import botan.tls.tls_heartbeats;
import botan.tls.tls_record;
import botan.tls.tls_seq_numbers;
import botan.utils.rounding;
import botan.utils.containers.multimap;
import botan.utils.loadstor;
import botan.utils.types;
// import string;
import botan.utils.containers.hashmap;

/**
* Generic interface for TLS endpoint
*/
class Channel
{
public:
    /**
    * Inject TLS traffic received from counterparty
    * @return a hint as the how many more bytes we need to process the
    *            current record (this may be 0 if on a record boundary)
    */
    size_t received_data(in ubyte* input, size_t input_size)
    {
        const auto get_cipherstate = (ushort epoch)
        { return this.read_cipher_state_epoch(epoch); };
        
        const size_t max_fragment_size = maximum_fragment_size();
        
        try
        {
            while (!is_closed() && input_size)
            {
                Secure_Vector!ubyte record;
                ulong record_sequence = 0;
                Record_Type record_type = NO_RECORD;
                Protocol_Version record_version;
                
                size_t consumed = 0;
                
                const size_t needed = read_record(m_readbuf,
                                                  input,
                                                  input_size,
                                                  consumed,
                                                  record,
                                                  &record_sequence,
                                                  &record_version,
                                                  &record_type,
                                                  sequence_numbers(),
                                                  get_cipherstate);
                
                assert(consumed <= input_size, "Record reader consumed sane amount");
                
                input += consumed;
                input_size -= consumed;
                
                assert(input_size == 0 || needed == 0, "Got a full record or consumed all input");
                
                if (input_size == 0 && needed != 0)
                    return needed; // need more data to complete record
                
                if (record.length > max_fragment_size)
                    throw new TLS_Exception(Alert.RECORD_OVERFLOW, "Plaintext record is too large");
                
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
                    
                    while (true)
                    {
                        if (Handshake_State pending = *m_pending_state) {
                            auto msg = pending.get_next_handshake_msg();
                            
                            if (msg.first == HANDSHAKE_NONE) // no full handshake yet
                                break;
                            
                            process_handshake_msg(active_state(), *pending,
                                                  msg.first, msg.second);
                        } else break;
                    }
                }
                else if (record_type == HEARTBEAT && peer_supports_heartbeats())
                {
                    if (!active_state())
                        throw new Unexpected_Message("Heartbeat sent before handshake done");
                    
                    Heartbeat_Message heartbeat = Heartbeat_Message(unlock(record));
                    
                    const Vector!ubyte payload = heartbeat.payload();
                    
                    if (heartbeat.is_request())
                    {
                        if (!pending_state())
                        {
                            Heartbeat_Message response = Heartbeat_Message(Heartbeat_Message.RESPONSE,
                                                       payload.ptr, payload.length);
                            
                            send_record(HEARTBEAT, response.contents());
                        }
                    }
                    else
                    {
                        m_alert_cb(Alert(Alert.HEARTBEAT_PAYLOAD), payload[]);
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
                    if (record.length > 0)
                        m_data_cb(record[]);
                }
                else if (record_type == ALERT)
                {
                    Alert alert_msg = Alert(record);
                    
                    if (alert_msg.type() == Alert.NO_RENEGOTIATION)
                    m_pending_state.clear();
                
                m_alert_cb(alert_msg, null);
                
                if (alert_msg.is_fatal())
                {
                    if (auto active = active_state())
                        m_session_manager.remove_entry(active.server_hello().session_id());
                }
                        
                if (alert_msg.type() == Alert.CLOSE_NOTIFY)
                    send_warning_alert(Alert.CLOSE_NOTIFY); // reply in kind
                            
                if (alert_msg.type() == Alert.CLOSE_NOTIFY || alert_msg.is_fatal())
                {
                    reset_state();
                    return 0;
                }
            }
            else
                throw new Unexpected_Message("Unexpected record type " ~ to!string(record_type) ~ " from counterparty");
            }
                    
            return 0; // on a record boundary
        }
        catch(TLS_Exception e)
        {
            send_fatal_alert(e.type());
            throw e;
        }
        catch(Integrity_Failure e)
        {
            send_fatal_alert(Alert.BAD_RECORD_MAC);
            throw e;
        }
        catch(Decoding_Error e)
        {
            send_fatal_alert(Alert.DECODE_ERROR);
            throw e;
        }
        catch(Throwable e)
        {
            send_fatal_alert(Alert.INTERNAL_ERROR);
            throw e;
        }
    }

    /**
    * Inject TLS traffic received from counterparty
    * @return a hint as the how many more bytes we need to process the
    *            current record (this may be 0 if on a record boundary)
    */
    size_t received_data(in Vector!ubyte buf)
    {
        return this.received_data(buf.ptr, buf.length);
    }

    /**
    * Inject plaintext intended for counterparty
    */
    void send(in ubyte* buf, size_t buf_size)
    {
        if (!is_active())
            throw new Exception("Data cannot be sent on inactive TLS connection");
        
        send_record_array(sequence_numbers().current_write_epoch(), APPLICATION_DATA, buf, buf_size);
    }

    /**
    * Inject plaintext intended for counterparty
    */
    void send(in string str)
    {
        this.send(cast(const ubyte*)(str.toStringz), str.length);
    }

    void send(in string val);

    /**
    * Inject plaintext intended for counterparty
    */
    void send(Alloc)(in Vector!( char, Alloc ) val)
    {
        send(val.ptr, val.length);
    }

    /**
    * Send a TLS alert message. If the alert is fatal, the internal
    * state (keys, etc) will be reset.
    * @param alert the Alert to send
    */
    void send_alert(in Alert alert)
    {
        if (alert.is_valid() && !is_closed())
        {
            try
            {
                send_record(ALERT, alert.serialize());
            }
            catch { /* swallow it */ }
        }
        
        if (alert.type() == Alert.NO_RENEGOTIATION)
            m_pending_state.clear();
        
        if (alert.is_fatal())
            if (auto active = active_state())
                m_session_manager.remove_entry(active.server_hello().session_id());
        
        if (alert.type() == Alert.CLOSE_NOTIFY || alert.is_fatal())
            reset_state();
    }

    /**
    * Send a warning alert
    */
    void send_warning_alert(Alert.Type type) { send_alert(Alert(type, false)); }

    /**
    * Send a fatal alert
    */
    void send_fatal_alert(Alert.Type type) { send_alert(Alert(type, true)); }

    /**
    * Send a close notification alert
    */
    void close() { send_warning_alert(Alert.CLOSE_NOTIFY); }

    /**
    * @return true iff the connection is active for sending application data
    */
    bool is_active() const
    {
        return (active_state() != null);
    }

    /**
    * @return true iff the connection has been definitely closed
    */
    bool is_closed() const
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

    /**
    * Attempt to renegotiate the session
    * @param force_full_renegotiation if true, require a full renegotiation,
    *                                            otherwise allow session resumption
    */
    void renegotiate(bool force_full_renegotiation = false)
    {
        if (pending_state()) // currently in handshake?
            return;
        
        if (Handshake_State active = active_state())
            initiate_handshake(create_handshake_state(active._version()),
                               force_full_renegotiation);
        else
            throw new Exception("Cannot renegotiate on inactive connection");
    }

    /**
    * @return true iff the peer supports heartbeat messages
    */
    bool peer_supports_heartbeats() const
    {
        if (Handshake_State active = active_state())
            return active.server_hello().supports_heartbeats();
        return false;
    }

    /**
    * @return true iff we are allowed to send heartbeat messages
    */
    bool heartbeat_sending_allowed() const
    {
        if (Handshake_State active = active_state())
            return active.server_hello().peer_can_send_heartbeats();
        return false;
    }

    /**
    * @return true iff the counterparty supports the secure
    * renegotiation extensions.
    */
    bool secure_renegotiation_supported() const;

    /**
    * Attempt to send a heartbeat message (if negotiated with counterparty)
    * @param payload will be echoed back
    * @param payload_size size of payload in bytes
    */
    void heartbeat(in ubyte* payload, size_t payload_size)
    {
        if (heartbeat_sending_allowed())
        {
            Heartbeat_Message heartbeat = Heartbeat_Message(Heartbeat_Message.REQUEST,
                                        payload, payload_size);
            
            send_record(HEARTBEAT, heartbeat.contents());
        }
    }

    /**
    * Attempt to send a heartbeat message (if negotiated with counterparty)
    */
    void heartbeat() { heartbeat(null, 0); }

    /**
    * @return certificate chain of the peer (may be empty)
    */
    Vector!X509_Certificate peer_cert_chain() const
    {
        if (Handshake_State active = active_state())
            return get_peer_cert_chain(*active);
        return Vector!X509_Certificate();
    }

    /**
    * Key material export (RFC 5705)
    * @param label a disambiguating label string
    * @param context a per-association context value
    * @param length the length of the desired key in bytes
    * @return key of length bytes
    */
    SymmetricKey key_material_export(in string label,
                                     in string context,
                                     size_t length) const
    {
        if (auto active = active_state())
        {
            Unique!KDF prf = active.protocol_specific_prf();
            
            const Secure_Vector!ubyte master_secret = active.session_keys().master_secret();
            
            Vector!ubyte salt;
            salt ~= label;
            salt ~= active.client_hello().random();
            salt ~= active.server_hello().random();
            
            if (context != "")
            {
                size_t context_size = context.length;
                if (context_size > 0xFFFF)
                    throw new Exception("key_material_export context is too long");
                salt.push_back(get_byte!ushort(0, context_size));
                salt.push_back(get_byte!ushort(1, context_size));
                salt ~= context;
            }
            
            return prf.derive_key(length, master_secret, salt);
        }
        else
            throw new Exception("key_material_export connection not active");
    }

    this(void delegate(in ubyte[]) output_fn,
         void delegate(in ubyte[]) data_cb,
         void delegate(Alert, in ubyte[]) alert_cb,
         bool delegate(in Session) handshake_cb,
         Session_Manager session_manager,
         RandomNumberGenerator rng,
         size_t reserved_io_buffer_size)
    {
        m_handshake_cb = handshake_cb;
        m_data_cb = data_cb;
        m_alert_cb = alert_cb;
        m_output_fn = output_fn;
        m_rng = rng;
        m_session_manager = session_manager;
        /* epoch 0 is plaintext, thus null cipher state */
        m_write_cipher_states[0] = null;
        m_read_cipher_states[0] = null;
        
        m_writebuf.reserve(reserved_io_buffer_size);
        m_readbuf.reserve(reserved_io_buffer_size);
    }

    ~this()
    {
        // So unique_ptr destructors run correctly
    }
protected:

    abstract void process_handshake_msg(const Handshake_State active_state,
                                                  Handshake_State pending_state,
                                                  Handshake_Type type,
                                                  in Vector!ubyte contents);

    abstract void initiate_handshake(Handshake_State state,
                                              bool force_full_renegotiation);

    abstract Vector!X509_Certificate
        get_peer_cert_chain(in Handshake_State state) const;

    abstract Handshake_State new_handshake_state(Handshake_IO io);

    Handshake_State create_handshake_state(Protocol_Version _version)
    {
        if (pending_state())
            throw new Internal_Error("create_handshake_state called during handshake");
        
        if (Handshake_State active = active_state())
        {
            Protocol_Version active_version = active._version();
            
            if (active_version.is_datagram_protocol() != _version.is_datagram_protocol())
                throw new Exception("Active state using version " ~ active_version.toString() ~
                                    " cannot change to " ~ _version.toString() ~ " in pending");
        }
        
        if (!m_sequence_numbers)
        {
            if (_version.is_datagram_protocol())
                m_sequence_numbers = new Datagram_Sequence_Numbers;
            else
                m_sequence_numbers = new Stream_Sequence_Numbers;
        }
        
        Unique!Handshake_IO io;
        if (_version.is_datagram_protocol())
            io = new Datagram_Handshake_IO(sequence_numbers(), &send_record_under_epoch);
        else
            io = new Stream_Handshake_IO(&send_record);
        
        m_pending_state = new_handshake_state(*io);
        
        if (auto active = active_state())
            m_pending_state.set_version(active._version());
        
        return *m_pending_state;
    }

    void activate_session()
    {
        std.algorithm.swap(m_active_state, m_pending_state);
        m_pending_state.clear();
        
        if (m_active_state._version().is_datagram_protocol())
        {
            // FIXME, remove old states when we are sure not needed anymore
        }
        else
        {
            // TLS is easy just remove all but the current state
            auto current_epoch = sequence_numbers().current_write_epoch();

            foreach (k, v; m_write_cipher_states) {
                if (k != current_epoch)
                    m_write_cipher_states.remove(k);
            }
            foreach (k, v; m_read_cipher_states) {
                if (k != current_epoch)
                    m_write_cipher_states.remove(k);
            }
        }
    }

    void change_cipher_spec_reader(Connection_Side side)
    {
        auto pending = pending_state();
        
        assert(pending && pending.server_hello(), "Have received server hello");
        
        if (pending.server_hello().compression_method() != NO_COMPRESSION)
            throw new Internal_Error("Negotiated unknown compression algorithm");
        
        sequence_numbers().new_read_cipher_state();
        
        const ushort epoch = sequence_numbers().current_read_epoch();
        
        assert(m_read_cipher_states.count(epoch) == 0, "No read cipher state currently set for next epoch");
        
        // flip side as we are reading
        Connection_Cipher_State read_state = Connection_Cipher_State(pending._version(),
                                                                     (side == CLIENT) ? SERVER : CLIENT,
                                                                     false,
                                                                     pending.ciphersuite(),
                                                                     pending.session_keys());
        
        m_read_cipher_states[epoch] = read_state;
    }

    void change_cipher_spec_writer(Connection_Side side)
    {
        auto pending = pending_state();
        
        assert(pending && pending.server_hello(), "Have received server hello");
        
        if (pending.server_hello().compression_method() != NO_COMPRESSION)
            throw new Internal_Error("Negotiated unknown compression algorithm");
        
        sequence_numbers().new_write_cipher_state();
        
        const ushort epoch = sequence_numbers().current_write_epoch();
        
        assert(m_write_cipher_states.count(epoch) == 0, "No write cipher state currently set for next epoch");
        
        Connection_Cipher_State write_state = new Connection_Cipher_State(pending._version(),
                                                                          side,
                                                                          true,
                                                                          pending.ciphersuite(),
                                                                          pending.session_keys());
        
        m_write_cipher_states[epoch] = write_state;
    }

    /* secure renegotiation handling */
    void secure_renegotiation_check(const Client_Hello client_hello)
    {
        const bool secure_renegotiation = client_hello.secure_renegotiation();
        
        if (auto active = active_state())
        {
            const bool active_sr = active.client_hello().secure_renegotiation();
            
            if (active_sr != secure_renegotiation)
                throw new TLS_Exception(Alert.HANDSHAKE_FAILURE, "Client changed its mind about secure renegotiation");
        }
        
        if (secure_renegotiation)
        {
            const Vector!ubyte data = client_hello.renegotiation_info();
            
            if (data != secure_renegotiation_data_for_client_hello())
                throw new TLS_Exception(Alert.HANDSHAKE_FAILURE, "Client sent bad values for secure renegotiation");
        }
    }

    void secure_renegotiation_check(const Server_Hello server_hello)
    {
        const bool secure_renegotiation = server_hello.secure_renegotiation();
        
        if (auto active = active_state())
        {
            const bool active_sr = active.client_hello().secure_renegotiation();
            
            if (active_sr != secure_renegotiation)
                throw new TLS_Exception(Alert.HANDSHAKE_FAILURE, "Server changed its mind about secure renegotiation");
        }
        
        if (secure_renegotiation)
        {
            const Vector!ubyte data = server_hello.renegotiation_info();
            
            if (data != secure_renegotiation_data_for_server_hello())
                throw new TLS_Exception(Alert.HANDSHAKE_FAILURE, "Server sent bad values for secure renegotiation");
        }
    }

    Vector!ubyte secure_renegotiation_data_for_client_hello() const
    {
        if (auto active = active_state())
            return active.client_finished().verify_data();
        return Vector!ubyte();
    }

    Vector!ubyte secure_renegotiation_data_for_server_hello() const
    {
        if (auto active = active_state())
        {
            Vector!ubyte buf = active.client_finished().verify_data();
            buf ~= active.server_finished().verify_data();
            return buf;
        }
        
        return Vector!ubyte();
    }

    bool secure_renegotiation_supported() const
    {
        if (auto active = active_state())
            return active.server_hello().secure_renegotiation();
        
        if (auto pending = pending_state())
            if (auto hello = pending.server_hello())
                return hello.secure_renegotiation();
        
        return false;
    }

    RandomNumberGenerator rng() { return m_rng; }

    Session_Manager session_manager() { return m_session_manager; }

    bool save_session(in Session session) const { return m_handshake_cb(session); }

private:

    size_t maximum_fragment_size() const
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

    void send_record(ubyte record_type, in Vector!ubyte record)
    {
        send_record_array(sequence_numbers().current_write_epoch(),
                          record_type, record.ptr, record.length);
    }

    void send_record_under_epoch(ushort epoch, ubyte record_type,
                                 in Vector!ubyte record)
    {
        send_record_array(epoch, record_type, record.ptr, record.length);
    }

    void send_record_array(ushort epoch, ubyte type, in ubyte* input, size_t length)
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
            write_record(cipher_state, type, input.ptr, 1);
            input += 1;
            length -= 1;
        }
        
        const size_t max_fragment_size = maximum_fragment_size();
        
        while (length)
        {
            const size_t sending = std.algorithm.min(length, max_fragment_size);
            write_record(cipher_state, type, input.ptr, sending);
            
            input += sending;
            length -= sending;
        }
    }

    void write_record(Connection_Cipher_State cipher_state,
                      ubyte record_type, in ubyte* input, size_t length)
    {
        assert(m_pending_state || m_active_state,
               "Some connection state exists");
        
        Protocol_Version record_version =
            (m_pending_state) ? (m_pending_state._version()) : (m_active_state._version());
        
        write_record(m_writebuf,
                     record_type,
                     input,
                     length,
                     record_version,
                     sequence_numbers().next_write_sequence(),
                     cipher_state,
                     m_rng);
        
        m_output_fn(m_writebuf[]);
    }

    Connection_Sequence_Numbers sequence_numbers() const
    {
        assert(m_sequence_numbers, "Have a sequence numbers object");
        return *m_sequence_numbers;
    }

    Connection_Cipher_State read_cipher_state_epoch(ushort epoch) const
    {
        auto i = m_read_cipher_states.get(epoch, Connection_Cipher_State.init);
        
        assert(i != Connection_Cipher_State.init, "Have a cipher state for the specified epoch");
        
        return i;
    }

    Connection_Cipher_State write_cipher_state_epoch(ushort epoch) const
    {
        auto i = m_write_cipher_states.get(epoch, Connection_Cipher_State.init);
        
        assert(i != Connection_Cipher_State.init, "Have a cipher state for the specified epoch");
        
        return i;
    }

    void reset_state()
    {
        m_active_state.clear();
        m_pending_state.clear();
        m_readbuf.clear();
        m_write_cipher_states.clear();
        m_read_cipher_states.clear();
    }

    const Handshake_State active_state() const { return *m_active_state; }

    const Handshake_State pending_state() const { return *m_pending_state; }

    /* callbacks */
    bool delegate(in Session) m_handshake_cb;
    void delegate(in ubyte[]) m_data_cb;
    void delegate(Alert, in ubyte[]) m_alert_cb;
    void delegate(in ubyte[]) m_output_fn;

    /* external state */
    RandomNumberGenerator m_rng;
    Session_Manager m_session_manager;

    /* sequence number state */
    Unique!Connection_Sequence_Numbers m_sequence_numbers;

    /* pending and active connection states */
    Unique!Handshake_State m_active_state;
    Unique!Handshake_State m_pending_state;

    /* cipher states for each epoch */
    HashMap!(ushort, Connection_Cipher_State) m_write_cipher_states;
    HashMap!(ushort, Connection_Cipher_State) m_read_cipher_states;

    /* I/O buffers */
    Secure_Vector!ubyte m_writebuf;
    Secure_Vector!ubyte m_readbuf;
}