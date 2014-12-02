/*
* TLS Client
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_client;

import botan.constants;
static if (BOTAN_HAS_TLS):

public import botan.tls.tls_channel;
public import botan.credentials.credentials_manager;
public import botan.tls.tls_server_info;
public import botan.rng.rng;
import botan.tls.tls_handshake_state;
import botan.tls.tls_messages;
import botan.utils.containers.multimap;
import botan.utils.types;

/**
* SSL/TLS Client
*/
final class TLS_Client : TLS_Channel
{
public:
    /**
    * Set up a new TLS client session
    *
    * @param socket_output_fn is called with data for the outbound socket
    *
    * @param proc_cb is called when new application data is received
    *
    * @param alert_cb is called when a TLS alert is received
    *
    * @param handshake_cb is called when a handshake is completed
    *
    * @param session_manager manages session state
    *
    * @param creds manages application/user credentials
    *
    * @param policy specifies other connection policy information
    *
    * @param rng a random number generator
    *
    * @param server_info is identifying information about the TLS server
    *
    * @param offer_version specifies which version we will offer
    *          to the TLS server.
    *
    * @param next_protocol allows the client to specify what the next
    *          protocol will be. For more information read
    *          http://technotes.googlecode.com/git/nextprotoneg.html.
    *
    *          If the function is not empty, NPN will be negotiated
    *          and if the server supports NPN the function will be
    *          called with the list of protocols the server advertised;
    *          the client should return the protocol it would like to use.
    *
    * @param reserved_io_buffer_size This many bytes of memory will
    *          be preallocated for the read and write buffers. Smaller
    *          values just mean reallocations and copies are more likely.
    */
    this(void delegate(in ubyte[]) socket_output_fn,
         void delegate(in ubyte[]) proc_cb,
         void delegate(in TLS_Alert, in ubyte[]) alert_cb,
         bool delegate(in TLS_Session) handshake_cb,
         TLS_Session_Manager session_manager,
         TLS_Credentials_Manager creds,
         in TLS_Policy policy,
         RandomNumberGenerator rng,
         in TLS_Server_Information server_info = TLS_Server_Information(),
         in TLS_Protocol_Version offer_version = TLS_Protocol_Version.latest_tls_version(),
         string delegate(string[]) next_protocol = null,
         size_t reserved_io_buffer_size = 16*1024)
    { 
        super(socket_output_fn, proc_cb, alert_cb, handshake_cb, session_manager, rng, reserved_io_buffer_size);
        m_policy = policy;
        m_creds = creds;
        m_info = server_info;
        const string srp_identifier = m_creds.srp_identifier("tls-client", m_info.hostname());
        
        Handshake_State state = create_handshake_state(offer_version);
        send_client_hello(state, false, offer_version, srp_identifier, next_protocol);
    }
private:
    override Vector!X509_Certificate
        get_peer_cert_chain(in Handshake_State state) const
    {
        if (state.server_certs())
            return state.server_certs().cert_chain();
        return Vector!X509_Certificate();
    }

    /*
    * Send a new client hello to renegotiate
    */
    override void initiate_handshake(Handshake_State state,
                            bool force_full_renegotiation)
    {
        send_client_hello(state,
                          force_full_renegotiation,
                          state._version());
    }

    void send_client_hello(Handshake_State state_base,
                           bool force_full_renegotiation,
                           TLS_Protocol_Version _version,
                           in string srp_identifier = "",
                           string delegate(string[]) next_protocol = null)
    {
        Client_Handshake_State state = cast(Client_Handshake_State)(state_base);
        
        if (state._version().is_datagram_protocol())
            state.set_expected_next(HELLO_VERIFY_REQUEST); // optional
        state.set_expected_next(SERVER_HELLO);
        
        state.client_npn_cb = next_protocol;
        
        const bool send_npn_request = cast(bool)(next_protocol);
        
        if (!force_full_renegotiation && !m_info.empty)
        {
            TLS_Session session_info;
            if (session_manager().load_from_server_info(m_info, session_info))
            {
                if (srp_identifier == "" || session_info.srp_identifier() == srp_identifier)
                {
                    state.client_hello(new Client_Hello(
                        state.handshake_io(),
                        state.hash(),
                        m_policy,
                        rng(),
                        secure_renegotiation_data_for_client_hello(),
                        session_info,
                        send_npn_request));
                    
                    state.resume_master_secret = session_info.master_secret();
                }
            }
        }
        
        if (!state.client_hello()) // not resuming
        {
            state.client_hello(new Client_Hello(
				               state.handshake_io(),
				               state.hash(),
				               _version,
				               m_policy,
				               rng(),
				               secure_renegotiation_data_for_client_hello(),
				               send_npn_request,
				               m_info.hostname(),
				               srp_identifier));
        }
        
        secure_renegotiation_check(state.client_hello());
    }

    /*
    * Process a handshake message
    */
    override void process_handshake_msg(in Handshake_State active_state,
                               Handshake_State state_base,
                               Handshake_Type type,
                               in Vector!ubyte contents)
    {
        Client_Handshake_State state = cast(Client_Handshake_State)(state_base);
        
        if (type == HELLO_REQUEST && active_state)
        {
            Hello_Request hello_request(contents);
            
            // Ignore request entirely if we are currently negotiating a handshake
            if (state.client_hello())
                return;
            
            if (!m_policy.allow_server_initiated_renegotiation() ||
                (!m_policy.allow_insecure_renegotiation() && !secure_renegotiation_supported()))
            {
                // RFC 5746 section 4.2
                send_warning_alert(TLS_Alert.NO_RENEGOTIATION);
                return;
            }
            
            this.initiate_handshake(state, false);
            
            return;
        }
        
        state.confirm_transition_to(type);
        
        if (type != HANDSHAKE_CCS && type != FINISHED && type != HELLO_VERIFY_REQUEST)
            state.hash().update(state.handshake_io().format(contents, type));
        
        if (type == HELLO_VERIFY_REQUEST)
        {
            state.set_expected_next(SERVER_HELLO);
            state.set_expected_next(HELLO_VERIFY_REQUEST); // might get it again
            
            Hello_Verify_Request hello_verify_request = scoped!Hello_Verify_Request(contents);

            state.hello_verify_request(hello_verify_request);
        }
        else if (type == SERVER_HELLO)
        {
            state.server_hello(new Server_Hello(contents));
            
            if (!state.client_hello().offered_suite(state.server_hello().ciphersuite()))
            {
                throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE,
                                        "TLS_Server replied with ciphersuite we didn't send");
            }
            
            if (!value_exists(state.client_hello().compression_methods(),
                              state.server_hello().compression_method()))
            {
                throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE,
                                        "TLS_Server replied with compression method we didn't send");
            }
            
            auto client_extn = state.client_hello().extension_types();
            auto server_extn = state.server_hello().extension_types();
            
            import std.algorithm : setDifference;
            import std.range : empty, array;
            auto diff = setDifference(server_extn, client_extn);
            if (!diff.empty)
            {
                throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE,
                                        "TLS_Server sent extension(s) " ~ diff.array.to!(string[]) ~ " but we did not request it");
            }
            
            state.set_version(state.server_hello()._version());
            
            secure_renegotiation_check(state.server_hello());
            
            const bool server_returned_same_session_id = !state.server_hello().session_id().empty &&
                                                         (state.server_hello().session_id() == state.client_hello().session_id());
            
            if (server_returned_same_session_id)
            {
                // successful resumption
                
                /*
                * In this case, we offered the version used in the original
                * session, and the server must resume with the same version.
                */
                if (state.server_hello()._version() != state.client_hello()._version())
                    throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE, "TLS_Server resumed session but with wrong version");
                
                state.compute_session_keys(state.resume_master_secret);
                
                if (state.server_hello().supports_session_ticket())
                    state.set_expected_next(NEW_SESSION_TICKET);
                else
                    state.set_expected_next(HANDSHAKE_CCS);
            }
            else
            {
                // new session
                
                if (state.client_hello()._version().is_datagram_protocol() !=
                    state.server_hello()._version().is_datagram_protocol())
                {
                    throw new TLS_Exception(TLS_Alert.PROTOCOL_VERSION, "TLS_Server replied with different protocol type than we offered");
                }
                
                if (state._version() > state.client_hello()._version())
                {
                    throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE, "TLS_Server replied with later version than in hello");
                }
                
                if (!m_policy.acceptable_protocol_version(state._version()))
                {
                    throw new TLS_Exception(TLS_Alert.PROTOCOL_VERSION, "TLS_Server version is unacceptable by policy");
                }
                
                if (state.ciphersuite().sig_algo() != "")
                {
                    state.set_expected_next(CERTIFICATE);
                }
                else if (state.ciphersuite().kex_algo() == "PSK")
                {
                    /* PSK is anonymous so no certificate/cert req message is
                        ever sent. The server may or may not send a server kex,
                        depending on if it has an identity hint for us.

                        (EC)DHE_PSK always sends a server key exchange for the
                        DH exchange portion.
                    */
                    
                    state.set_expected_next(SERVER_KEX);
                    state.set_expected_next(SERVER_HELLO_DONE);
                }
                else if (state.ciphersuite().kex_algo() != "RSA")
                {
                    state.set_expected_next(SERVER_KEX);
                }
                else
                {
                    state.set_expected_next(CERTIFICATE_REQUEST); // optional
                    state.set_expected_next(SERVER_HELLO_DONE);
                }
            }
        }
        else if (type == CERTIFICATE)
        {
            if (state.ciphersuite().kex_algo() != "RSA")
            {
                state.set_expected_next(SERVER_KEX);
            }
            else
            {
                state.set_expected_next(CERTIFICATE_REQUEST); // optional
                state.set_expected_next(SERVER_HELLO_DONE);
            }
            
            state.server_certs(new Certificate(contents));
            
            const Vector!X509_Certificate server_certs = state.server_certs().cert_chain();
            
            if (server_certs.empty)
                throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE, "TLS_Client: No certificates sent by server");
            
            try
            {
                m_creds.verify_certificate_chain("tls-client", m_info.hostname(), server_certs);
            }
            catch(Exception e)
            {
                throw new TLS_Exception(TLS_Alert.BAD_CERTIFICATE, e.msg);
            }
            
            Unique!Public_Key peer_key = server_certs[0].subject_public_key();
            
            if (peer_key.algo_name != state.ciphersuite().sig_algo())
                throw new TLS_Exception(TLS_Alert.ILLEGAL_PARAMETER, "Certificate key type did not match ciphersuite");
            
            state.server_public_key = peer_key;
        }
        else if (type == SERVER_KEX)
        {
            state.set_expected_next(CERTIFICATE_REQUEST); // optional
            state.set_expected_next(SERVER_HELLO_DONE);
            
            state.server_kex(new Server_Key_Exchange(contents,
                                                     state.ciphersuite().kex_algo(),
                                                     state.ciphersuite().sig_algo(),
                                                     state._version()));
            
            if (state.ciphersuite().sig_algo() != "")
            {
                const Public_Key server_key = state.get_server_public_Key();
                
                if (!state.server_kex().verify(server_key, state))
                {
                    throw new TLS_Exception(TLS_Alert.DECRYPT_ERROR, "Bad signature on server key exchange");
                }
            }
        }
        else if (type == CERTIFICATE_REQUEST)
        {
            state.set_expected_next(SERVER_HELLO_DONE);
            state.cert_req(new Certificate_Req(contents, state._version()));
        }
        else if (type == SERVER_HELLO_DONE)
        {
            state.server_hello_done(new Server_Hello_Done(contents));
            
            if (state.received_handshake_msg(CERTIFICATE_REQUEST))
            {
                const Vector!string types =    state.cert_req().acceptable_cert_types();
                
                Vector!X509_Certificate client_certs = m_creds.cert_chain(types, "tls-client", m_info.hostname());
                
                state.client_certs(new Certificate(state.handshake_io(), state.hash(), client_certs));
            }
            
            state.client_kex(new Client_Key_Exchange(state.handshake_io(),
                                                     state,
                                                     m_policy,
                                                     m_creds,
                                                     state.server_public_key.get(),
                                                     m_info.hostname(),
                                                     rng()));
            
            state.compute_session_keys();
            
            if (state.received_handshake_msg(CERTIFICATE_REQUEST) &&
                !state.client_certs().empty)
            {
                Private_Key priv_key =    m_creds.private_key_for(state.client_certs().cert_chain()[0], "tls-client",    m_info.hostname());
                
                state.client_verify(new Certificate_Verify(state.handshake_io(),
                                                           state,
                                                           m_policy,
                                                           rng(),
                                                           priv_key));
            }
            
            state.handshake_io().send(scoped!Change_Cipher_Spec());
            
            change_cipher_spec_writer(CLIENT);
            
            if (state.server_hello().next_protocol_notification())
            {
                const string protocol = state.client_npn_cb(state.server_hello().next_protocols());
                
                state.next_protocol(new Next_Protocol(state.handshake_io(), state.hash(), protocol));
            }
            
            state.client_finished(new Finished(state.handshake_io(), state, CLIENT));
            
            if (state.server_hello().supports_session_ticket())
                state.set_expected_next(NEW_SESSION_TICKET);
            else
                state.set_expected_next(HANDSHAKE_CCS);
        }
        else if (type == NEW_SESSION_TICKET)
        {
            state.new_session_ticket(new New_Session_Ticket(contents));
            
            state.set_expected_next(HANDSHAKE_CCS);
        }
        else if (type == HANDSHAKE_CCS)
        {
            state.set_expected_next(FINISHED);
            
            change_cipher_spec_reader(CLIENT);
        }
        else if (type == FINISHED)
        {
            state.server_finished(new Finished(contents));
            
            if (!state.server_finished().verify(state, SERVER))
                throw new TLS_Exception(TLS_Alert.DECRYPT_ERROR, "Finished message didn't verify");
            
            state.hash().update(state.handshake_io().format(contents, type));
            
            if (!state.client_finished()) // session resume case
            {
                state.handshake_io().send(scoped!Change_Cipher_Spec());
                
                change_cipher_spec_writer(CLIENT);
                
                if (state.server_hello().next_protocol_notification())
                {
                    const string protocol = state.client_npn_cb(state.server_hello().next_protocols());
                    
                    state.next_protocol(new Next_Protocol(state.handshake_io(), state.hash(), protocol));
                }
                
                state.client_finished(new Finished(state.handshake_io(), state, CLIENT));
            }
            
            Vector!ubyte session_id = state.server_hello().session_id();
            
            const Vector!ubyte session_ticket = state.session_ticket();
            
            if (session_id.empty && !session_ticket.empty)
                session_id = make_hello_random(rng());
            
            TLS_Session session_info = TLS_Session(session_id,
                                            state.session_keys().master_secret(),
                                            state.server_hello()._version(),
                                            state.server_hello().ciphersuite(),
                                            state.server_hello().compression_method(),
                                            CLIENT,
                                            state.server_hello().fragment_size(),
                                            get_peer_cert_chain(state),
                                            session_ticket,
                                            m_info,
                                            "");
            
            const bool should_save = save_session(session_info);
            
            if (!session_id.empty)
            {
                if (should_save)
                    session_manager().save(session_info);
                else
                    session_manager().remove_entry(session_info.session_id());
            }
            
            activate_session();
        }
        else
            throw new TLS_Unexpected_Message("Unknown handshake message received");
    }

    override Handshake_State new_handshake_state(Handshake_IO io)
    {
        return new Client_Handshake_State(io);
    }

    const TLS_Policy m_policy;
    TLS_Credentials_Manager m_creds;
    const TLS_Server_Information m_info;
}


private final class Client_Handshake_State : Handshake_State
{
public:
    
    this(Handshake_IO io, void delegate(in Handshake_Message) msg_callback) 
    { 
        super(io, msg_callback);
    }
    
    const Public_Key get_server_public_Key() const
    {
        assert(server_public_key, "TLS_Server sent us a certificate");
        return *server_public_key;
    }
    
    // Used during session resumption
    Secure_Vector!ubyte resume_master_secret;
    
    Unique!Public_Key server_public_key;
    
    // Used by client using NPN
    string delegate(Vector!string) client_npn_cb;
}