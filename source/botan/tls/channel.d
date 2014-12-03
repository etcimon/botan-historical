/*
* TLS Channel
* (C) 2011,2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.channel;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

public import botan.cert.x509.x509cert;
public import botan.tls.policy;
public import botan.tls.session;
public import botan.tls.alert;
public import botan.tls.session_manager;
public import botan.tls.version_;
public import botan.tls.exceptn;
public import botan.rng.rng;
import botan.tls.handshake_state;
import botan.tls.messages;
import botan.tls.heartbeats;
import botan.tls.record;
import botan.tls.seq_numbers;
import botan.utils.rounding;
import botan.utils.containers.multimap;
import botan.utils.loadstor;
import botan.utils.types;
// import string;
import botan.utils.containers.hashmap;

/**
* Generic interface for TLS endpoint
*/
class TLSChannel
{
public:
    /**
    * Inject TLS traffic received from counterparty
    * @return a hint as the how many more bytes we need to process the
    *            current record (this may be 0 if on a record boundary)
    */
    size_t receivedData(in ubyte* input, size_t input_size)
    {
        const auto get_cipherstate = (ushort epoch)
        { return this.read_cipher_state_epoch(epoch); };
        
        const size_t max_fragment_size = maximum_fragment_size();
        
        try
        {
            while (!is_closed() && input_size)
            {
                SecureVector!ubyte record;
                ulong record_sequence = 0;
                Record_Type record_type = NO_RECORD;
                TLSProtocolVersion record_version;
                
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
                    throw new TLSException(TLSAlert.RECORD_OVERFLOW, "Plaintext record is too large");
                
                if (record_type == HANDSHAKE || record_type == CHANGE_CIPHER_SPEC)
                {
                    if (!m_pending_state)
                    {
                        createHandshakeState(record_version);
                        if (record_version.isDatagramProtocol())
                            sequence_numbers().readAccept(record_sequence);
                    }
                    
                    m_pending_state.handshakeIo().addRecord(unlock(record),
                                                              record_type,
                                                              record_sequence);
                    
                    while (true)
                    {
                        if (HandshakeState pending = *m_pending_state) {
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
                        throw new TLSUnexpectedMessage("Heartbeat sent before handshake done");
                    
                    Heartbeat_Message heartbeat = Heartbeat_Message(unlock(record));
                    
                    const Vector!ubyte payload = heartbeat.payload();
                    
                    if (heartbeat.isRequest())
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
                        m_alert_cb(TLSAlert(TLSAlert.HEARTBEAT_PAYLOAD), payload[]);
                    }
                }
                else if (record_type == APPLICATION_DATA)
                {
                    if (!active_state())
                        throw new TLSUnexpectedMessage("Application data before handshake done");
                            
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
                    TLSAlert alert_msg = TLSAlert(record);
                    
                    if (alert_msg.type() == TLSAlert.NO_RENEGOTIATION)
                    m_pending_state.clear();
                
                m_alert_cb(alert_msg, null);
                
                if (alert_msg.isFatal())
                {
                    if (auto active = active_state())
                        m_session_manager.removeEntry(active.serverHello().sessionId());
                }
                        
                if (alert_msg.type() == TLSAlert.CLOSE_NOTIFY)
                    send_warning_alert(TLSAlert.CLOSE_NOTIFY); // reply in kind
                            
                if (alert_msg.type() == TLSAlert.CLOSE_NOTIFY || alert_msg.isFatal())
                {
                    reset_state();
                    return 0;
                }
            }
            else
                throw new TLSUnexpectedMessage("Unexpected record type " ~ to!string(record_type) ~ " from counterparty");
            }
                    
            return 0; // on a record boundary
        }
        catch(TLSException e)
        {
            send_fatal_alert(e.type());
            throw e;
        }
        catch(IntegrityFailure e)
        {
            send_fatal_alert(TLSAlert.BAD_RECORD_MAC);
            throw e;
        }
        catch(DecodingError e)
        {
            send_fatal_alert(TLSAlert.DECODE_ERROR);
            throw e;
        }
        catch(Throwable e)
        {
            send_fatal_alert(TLSAlert.INTERNAL_ERROR);
            throw e;
        }
    }

    /**
    * Inject TLS traffic received from counterparty
    * @return a hint as the how many more bytes we need to process the
    *            current record (this may be 0 if on a record boundary)
    */
    size_t receivedData(in Vector!ubyte buf)
    {
        return this.receivedData(buf.ptr, buf.length);
    }

    /**
    * Inject plaintext intended for counterparty
    */
    void send(in ubyte* buf, size_t buf_size)
    {
        if (!is_active())
            throw new Exception("Data cannot be sent on inactive TLS connection");
        
        send_record_array(sequence_numbers().currentWriteEpoch(), APPLICATION_DATA, buf, buf_size);
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
    * @param alert = the TLSAlert to send
    */
    void sendAlert(in TLSAlert alert)
    {
        if (alert.isValid() && !is_closed())
        {
            try
            {
                send_record(ALERT, alert.serialize());
            }
            catch (Throwable) { /* swallow it */ }
        }
        
        if (alert.type() == TLSAlert.NO_RENEGOTIATION)
            m_pending_state.clear();
        
        if (alert.isFatal())
            if (auto active = active_state())
                m_session_manager.removeEntry(active.serverHello().sessionId());
        
        if (alert.type() == TLSAlert.CLOSE_NOTIFY || alert.isFatal())
            reset_state();
    }

    /**
    * Send a warning alert
    */
    void sendWarningAlert(TLSAlertType type) { send_alert(TLSAlert(type, false)); }

    /**
    * Send a fatal alert
    */
    void sendFatalAlert(TLSAlertType type) { send_alert(TLSAlert(type, true)); }

    /**
    * Send a close notification alert
    */
    void close() { send_warning_alert(TLSAlert.CLOSE_NOTIFY); }

    /**
    * @return true iff the connection is active for sending application data
    */
    bool isActive() const
    {
        return (active_state() != null);
    }

    /**
    * @return true iff the connection has been definitely closed
    */
    bool isClosed() const
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
    * @param force_full_renegotiation = if true, require a full renegotiation,
    *                                            otherwise allow session resumption
    */
    void renegotiate(bool force_full_renegotiation = false)
    {
        if (pending_state()) // currently in handshake?
            return;
        
        if (HandshakeState active = active_state())
            initiate_handshake(createHandshakeState(active.Version()),
                               force_full_renegotiation);
        else
            throw new Exception("Cannot renegotiate on inactive connection");
    }

    /**
    * @return true iff the peer supports heartbeat messages
    */
    bool peerSupportsHeartbeats() const
    {
        if (HandshakeState active = active_state())
            return active.serverHello().supportsHeartbeats();
        return false;
    }

    /**
    * @return true iff we are allowed to send heartbeat messages
    */
    bool heartbeatSendingAllowed() const
    {
        if (HandshakeState active = active_state())
            return active.serverHello().peerCanSendHeartbeats();
        return false;
    }

    /**
    * @return true iff the counterparty supports the secure
    * renegotiation extensions.
    */
    bool secureRenegotiationSupported() const;

    /**
    * Attempt to send a heartbeat message (if negotiated with counterparty)
    * @param payload = will be echoed back
    * @param payload_size = size of payload in bytes
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
    Vector!X509Certificate peerCertChain() const
    {
        if (HandshakeState active = active_state())
            return getPeerCertChain(*active);
        return Vector!X509Certificate();
    }

    /**
    * Key material export (RFC 5705)
    * @param label = a disambiguating label string
    * @param context = a per-association context value
    * @param length = the length of the desired key in bytes
    * @return key of length bytes
    */
    SymmetricKey keyMaterialExport(in string label,
                                     in string context,
                                     size_t length) const
    {
        if (auto active = active_state())
        {
            Unique!KDF prf = active.protocolSpecificPrf();
            
            const SecureVector!ubyte master_secret = active.sessionKeys().masterSecret();
            
            Vector!ubyte salt;
            salt ~= label;
            salt ~= active.clientHello().random();
            salt ~= active.serverHello().random();
            
            if (context != "")
            {
                size_t context_size = context.length;
                if (context_size > 0xFFFF)
                    throw new Exception("key_material_export context is too long");
                salt.pushBack(get_byte!ushort(0, context_size));
                salt.pushBack(get_byte!ushort(1, context_size));
                salt ~= context;
            }
            
            return prf.deriveKey(length, master_secret, salt);
        }
        else
            throw new Exception("key_material_export connection not active");
    }

    this(void delegate(in ubyte[]) output_fn,
         void delegate(in ubyte[]) data_cb,
         void delegate(in TLSAlert, in ubyte[]) alert_cb,
         bool delegate(in TLSSession) handshake_cb,
         TLSSessionManager session_manager,
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

    abstract void processHandshakeMsg(in HandshakeState active_state,
                                                  HandshakeState pending_state,
                                                  HandshakeType type,
                                                  in Vector!ubyte contents);

    abstract void initiateHandshake(HandshakeState state,
                                              bool force_full_renegotiation);

    abstract Vector!X509Certificate
        getPeerCertChain(in HandshakeState state) const;

    abstract HandshakeState newHandshakeState(HandshakeIO io);

    HandshakeState createHandshakeState(TLSProtocolVersion _version)
    {
        if (pending_state())
            throw new InternalError("createHandshakeState called during handshake");
        
        if (HandshakeState active = active_state())
        {
            TLSProtocolVersion active_version = active.Version();
            
            if (active_version.isDatagramProtocol() != _version.isDatagramProtocol())
                throw new Exception("Active state using version " ~ active_version.toString() ~
                                    " cannot change to " ~ _version.toString() ~ " in pending");
        }
        
        if (!m_sequence_numbers)
        {
            if (_version.isDatagramProtocol())
                m_sequence_numbers = new DatagramSequenceNumbers;
            else
                m_sequence_numbers = new StreamSequenceNumbers;
        }
        
        Unique!Handshake_IO io;
        if (_version.isDatagramProtocol())
            io = new DatagramHandshakeIO(sequence_numbers(), &send_record_under_epoch);
        else
            io = new StreamHandshakeIO(&send_record);
        
        m_pending_state = new_handshake_state(*io);
        
        if (auto active = active_state())
            m_pending_state.setVersion(active.Version());
        
        return *m_pending_state;
    }

    void activateSession()
    {
        std.algorithm.swap(m_active_state, m_pending_state);
        m_pending_state.clear();
        
        if (m_active_state.Version().isDatagramProtocol())
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

    void changeCipherSpecReader(ConnectionSide side)
    {
        auto pending = pending_state();
        
        assert(pending && pending.serverHello(), "Have received server hello");
        
        if (pending.serverHello().compressionMethod() != NO_COMPRESSION)
            throw new InternalError("Negotiated unknown compression algorithm");
        
        sequence_numbers().newReadCipherState();
        
        const ushort epoch = sequence_numbers().current_read_epoch();
        
        assert(m_read_cipher_states.count(epoch) == 0, "No read cipher state currently set for next epoch");
        
        // flip side as we are reading
        ConnectionCipherState read_state = ConnectionCipherState(pending.Version(),
                                                                     (side == CLIENT) ? SERVER : CLIENT,
                                                                     false,
                                                                     pending.ciphersuite(),
                                                                     pending.sessionKeys());
        
        m_read_cipher_states[epoch] = read_state;
    }

    void changeCipherSpecWriter(ConnectionSide side)
    {
        auto pending = pending_state();
        
        assert(pending && pending.serverHello(), "Have received server hello");
        
        if (pending.serverHello().compressionMethod() != NO_COMPRESSION)
            throw new InternalError("Negotiated unknown compression algorithm");
        
        sequence_numbers().newWriteCipherState();
        
        const ushort epoch = sequence_numbers().current_write_epoch();
        
        assert(m_write_cipher_states.count(epoch) == 0, "No write cipher state currently set for next epoch");
        
        ConnectionCipherState write_state = new ConnectionCipherState(pending.Version(),
                                                                          side,
                                                                          true,
                                                                          pending.ciphersuite(),
                                                                          pending.sessionKeys());
        
        m_write_cipher_states[epoch] = write_state;
    }

    /* secure renegotiation handling */
    void secureRenegotiationCheck(const ClientHello client_hello)
    {
        const bool secure_renegotiation = client_hello.secureRenegotiation();
        
        if (auto active = active_state())
        {
            const bool active_sr = active.clientHello().secureRenegotiation();
            
            if (active_sr != secure_renegotiation)
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLS_Client changed its mind about secure renegotiation");
        }
        
        if (secure_renegotiation)
        {
            const Vector!ubyte data = client_hello.renegotiation_info();
            
            if (data != secureRenegotiationDataForClientHello())
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLS_Client sent bad values for secure renegotiation");
        }
    }

    void secureRenegotiationCheck(const ServerHello server_hello)
    {
        const bool secure_renegotiation = server_hello.secureRenegotiation();
        
        if (auto active = active_state())
        {
            const bool active_sr = active.clientHello().secureRenegotiation();
            
            if (active_sr != secure_renegotiation)
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLS_Server changed its mind about secure renegotiation");
        }
        
        if (secure_renegotiation)
        {
            const Vector!ubyte data = server_hello.renegotiation_info();
            
            if (data != secureRenegotiationDataForServerHello())
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "TLS_Server sent bad values for secure renegotiation");
        }
    }

    Vector!ubyte secureRenegotiationDataForClientHello() const
    {
        if (auto active = active_state())
            return active.clientFinished().verifyData();
        return Vector!ubyte();
    }

    Vector!ubyte secureRenegotiationDataForServerHello() const
    {
        if (auto active = active_state())
        {
            Vector!ubyte buf = active.client_finished().verify_data();
            buf ~= active.serverFinished().verifyData();
            return buf;
        }
        
        return Vector!ubyte();
    }

    bool secureRenegotiationSupported() const
    {
        if (auto active = active_state())
            return active.serverHello().secureRenegotiation();
        
        if (auto pending = pending_state())
            if (auto hello = pending.serverHello())
                return hello.secureRenegotiation();
        
        return false;
    }

    RandomNumberGenerator rng() { return m_rng; }

    TLSSessionManager sessionManager() { return m_session_manager; }

    bool saveSession(in TLSSession session) const { return m_handshake_cb(session); }

private:

    size_t maximumFragmentSize() const
    {
        // should we be caching this value?
        
        if (auto pending = pending_state())
            if (auto server_hello = pending.serverHello())
                if (size_t frag = server_hello.fragmentSize())
                    return frag;
        
        if (auto active = active_state())
            if (size_t frag = active.serverHello().fragmentSize())
                return frag;
        
        return MAX_PLAINTEXT_SIZE;
    }

    void sendRecord(ubyte record_type, in Vector!ubyte record)
    {
        send_record_array(sequence_numbers().currentWriteEpoch(),
                          record_type, record.ptr, record.length);
    }

    void sendRecordUnderEpoch(ushort epoch, ubyte record_type,
                                 in Vector!ubyte record)
    {
        send_record_array(epoch, record_type, record.ptr, record.length);
    }

    void sendRecordArray(ushort epoch, ubyte type, in ubyte* input, size_t length)
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
        
        if (type == APPLICATION_DATA && cipher_state.cbcWithoutExplicitIv())
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

    void writeRecord(ConnectionCipherState cipher_state,
                      ubyte record_type, in ubyte* input, size_t length)
    {
        assert(m_pending_state || m_active_state,
               "Some connection state exists");
        
        TLSProtocolVersion record_version =
            (m_pending_state) ? (m_pending_state.Version()) : (m_active_state.Version());
        
        write_record(m_writebuf,
                     record_type,
                     input,
                     length,
                     record_version,
                     sequence_numbers().nextWriteSequence(),
                     cipher_state,
                     m_rng);
        
        m_output_fn(m_writebuf[]);
    }

    ConnectionSequenceNumbers sequenceNumbers() const
    {
        assert(m_sequence_numbers, "Have a sequence numbers object");
        return *m_sequence_numbers;
    }

    ConnectionCipherState readCipherStateEpoch(ushort epoch) const
    {
        auto i = m_read_cipher_states.get(epoch, ConnectionCipherState.init);
        
        assert(i != ConnectionCipherState.init, "Have a cipher state for the specified epoch");
        
        return i;
    }

    ConnectionCipherState writeCipherStateEpoch(ushort epoch) const
    {
        auto i = m_write_cipher_states.get(epoch, ConnectionCipherState.init);
        
        assert(i != ConnectionCipherState.init, "Have a cipher state for the specified epoch");
        
        return i;
    }

    void resetState()
    {
        m_active_state.clear();
        m_pending_state.clear();
        m_readbuf.clear();
        m_write_cipher_states.clear();
        m_read_cipher_states.clear();
    }

    HandshakeState activeState() const { return *m_active_state; }

    HandshakeState pendingState() const { return *m_pending_state; }

    /* callbacks */
    bool delegate(in TLSSession) m_handshake_cb;
    void delegate(in ubyte[]) m_data_cb;
    void delegate(in TLSAlert, in ubyte[]) m_alert_cb;
    void delegate(in ubyte[]) m_output_fn;

    /* external state */
    RandomNumberGenerator m_rng;
    TLS_Session_Manager m_session_manager;

    /* sequence number state */
    Unique!Connection_Sequence_Numbers m_sequence_numbers;

    /* pending and active connection states */
    Unique!HandshakeState m_active_state;
    Unique!HandshakeState m_pending_state;

    /* cipher states for each epoch */
    HashMap!(ushort, ConnectionCipherState) m_write_cipher_states;
    HashMap!(ushort, ConnectionCipherState) m_read_cipher_states;

    /* I/O buffers */
    SecureVector!ubyte m_writebuf;
    SecureVector!ubyte m_readbuf;
}