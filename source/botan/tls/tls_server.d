/*
* TLS Server
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_server;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.tls.tls_channel;
import botan.credentials.credentials_manager;
import botan.tls.tls_handshake_state;
import botan.tls.tls_messages;
import botan.tls.tls_alert;
import botan.rng.rng;
import botan.utils.containers.multimap;
import botan.utils.containers.hashmap;
import botan.utils.types;
import std.datetime;

/**
* TLS Server
*/
final class TLS_Server : TLS_Channel
{
public:
    /**
    * TLS_Server initialization
    */
    this(void delegate(ref ubyte[]) output_fn,
         void delegate(in ubyte[]) data_cb,
         void delegate(TLS_Alert, in ubyte[]) alert_cb,
         bool delegate(in TLS_Session) handshake_cb,
         TLS_Session_Manager session_manager,
         TLS_Credentials_Manager creds,
         const TLS_Policy policy,
         RandomNumberGenerator rng,
         in Vector!string next_protocols = Vector!string(),
         size_t io_buf_sz = 16*1024) 
    {
        super(output_fn, data_cb, alert_cb, handshake_cb, session_manager, rng, io_buf_sz);
        m_policy = policy;
        m_creds = creds;
        m_possible_protocols = next_protocols;
    }

    /**
    * Return the protocol notification set by the client (using the
    * NPN extension) for this connection, if any
    */
    string next_protocol() const { return m_next_protocol; }

private:
    override Vector!X509_Certificate get_peer_cert_chain(in Handshake_State state) const
    {
        if (state.client_certs())
            return state.client_certs().cert_chain();
        return Vector!X509_Certificate();
    }

    /*
    * Send a hello request to the client
    */
    override void initiate_handshake(Handshake_State state,
                            bool force_full_renegotiation)
    {
        (cast(Server_Handshake_State)state).allow_session_resumption = !force_full_renegotiation;
        
        auto hello_req = scoped!Hello_Request(state.handshake_io());
    }

    /*
    * Process a handshake message
    */
    override void process_handshake_msg(const Handshake_State active_state,
                                        Handshake_State state_base,
                                        Handshake_Type type,
                                        in Vector!ubyte contents)
    {
        Server_Handshake_State state = cast(Server_Handshake_State)(state_base);
        
        state.confirm_transition_to(type);
        
        /*
        * The change cipher spec message isn't technically a handshake
        * message so it's not included in the hash. The finished and
        * certificate verify messages are verified based on the current
        * state of the hash *before* this message so we delay adding them
        * to the hash computation until we've processed them below.
        */
        if (type != HANDSHAKE_CCS && type != FINISHED && type != CERTIFICATE_VERIFY)
        {
            if (type == CLIENT_HELLO_SSLV2)
                state.hash().update(contents);
            else
                state.hash().update(state.handshake_io().format(contents, type));
        }
        
        if (type == CLIENT_HELLO || type == CLIENT_HELLO_SSLV2)
        {
            const bool initial_handshake = !active_state;
            
            if (!m_policy.allow_insecure_renegotiation() &&
                !(initial_handshake || secure_renegotiation_supported()))
            {
                send_warning_alert(TLS_Alert.NO_RENEGOTIATION);
                return;
            }
            
            state.client_hello(new Client_Hello(contents, type));
            
            TLS_Protocol_Version client_version = state.client_hello()._version();
            
            TLS_Protocol_Version negotiated_version;
            
            if ((initial_handshake && client_version.known_version()) ||
                (!initial_handshake && client_version == active_state._version()))
            {
                /*
                Common cases: new client hello with some known version, or a
                renegotiation using the same version as previously
                negotiated.
                */
                
                negotiated_version = client_version;
            }
            else if (!initial_handshake && (client_version != active_state._version()))
            {
                /*
                * If this is a renegotiation, and the client has offered a
                * later version than what it initially negotiated, negotiate
                * the old version. This matches OpenSSL's behavior. If the
                * client is offering a version earlier than what it initially
                * negotiated, reject as a probable attack.
                */
                if (active_state._version() > client_version)
                {
                    throw new TLS_Exception(TLS_Alert.PROTOCOL_VERSION,
                                            "TLS_Client negotiated " ~
                                            active_state._version().toString() ~
                                            " then renegotiated with " ~
                                            client_version.toString());
                }
                else
                    negotiated_version = active_state._version();
            }
            else
            {
                /*
                New negotiation using a version we don't know. Offer
                them the best we currently know.
                */
                negotiated_version = client_version.best_known_match();
            }
            
            if (!m_policy.acceptable_protocol_version(negotiated_version))
            {
                throw new TLS_Exception(TLS_Alert.PROTOCOL_VERSION,
                                        "TLS_Client version is unacceptable by policy");
            }
            
            if (!initial_handshake && state.client_hello().next_protocol_notification())
                throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE,
                                        "TLS_Client included NPN extension for renegotiation");
            
            secure_renegotiation_check(state.client_hello());
            
            state.set_version(negotiated_version);

            TLS_Session session_info;
            const bool resuming = state.allow_session_resumption &&
                                    check_for_resume(session_info,
                                                     session_manager(),
                                                     m_creds,
                                                     state.client_hello(),
                                                     TickDuration.from!"seconds"(m_policy.session_ticket_lifetime()).to!Duration);
            
            bool have_session_ticket_key = false;
            
            try
            {
                have_session_ticket_key = m_creds.psk("tls-server", "session-ticket", "").length > 0;
            }
            catch {}

            if (resuming)
            {
                // resume session
                
                const bool offer_new_session_ticket = (state.client_hello().supports_session_ticket() &&
                                                        state.client_hello().session_ticket().empty &&
                                                        have_session_ticket_key);
                
                state.server_hello(new Server_Hello(state.handshake_io(),
                                                    state.hash(),
                                                    m_policy,
                                                    state.client_hello().session_id(),
                                                    TLS_Protocol_Version(session_info._version()),
                                                    session_info.ciphersuite_code(),
                                                    session_info.compression_method(),
                                                    session_info.fragment_size(),
                                                    state.client_hello().secure_renegotiation(),
                                                    secure_renegotiation_data_for_server_hello(),
                                                    offer_new_session_ticket,
                                                    state.client_hello().next_protocol_notification(),
                                                    m_possible_protocols,
                                                    state.client_hello().supports_heartbeats(),
                                                    rng()));
                
                secure_renegotiation_check(state.server_hello());
                
                state.compute_session_keys(session_info.master_secret());
                
                if (!save_session(session_info))
                {
                    session_manager().remove_entry(session_info.session_id());
                    
                    if (state.server_hello().supports_session_ticket()) // send an empty ticket
                    {
                        state.new_session_ticket(new New_Session_Ticket(state.handshake_io(), state.hash()));
                    }
                }
                
                if (state.server_hello().supports_session_ticket() && !state.new_session_ticket())
                {
                    try
                    {
                        const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");
                        
                        state.new_session_ticket(new New_Session_Ticket(state.handshake_io(),
                                                                        state.hash(),
                                                                        session_info.encrypt(ticket_key, rng()),
                                                                        m_policy.session_ticket_lifetime()));
                    }
                    catch {}
                    
                    if (!state.new_session_ticket())
                    {
                        state.new_session_ticket(new New_Session_Ticket(state.handshake_io(), state.hash()));
                    }
                }
                
                state.handshake_io().send(scoped!Change_Cipher_Spec());
                
                change_cipher_spec_writer(SERVER);
                
                state.server_finished(new Finished(state.handshake_io(), state, SERVER));
                
                state.set_expected_next(HANDSHAKE_CCS);
            }
            else // new session
            {
                HashMap!(string, Vector!X509_Certificate) cert_chains;
                
                const string sni_hostname = state.client_hello().sni_hostname();
                
                cert_chains = get_server_certs(sni_hostname, m_creds);
                
                if (sni_hostname != "" && cert_chains.empty)
                {
                    cert_chains = get_server_certs("", m_creds);
                        
                    /*
                    * Only send the unrecognized_name alert if we couldn't
                    * find any certs for the requested name but did find at
                    * least one cert to use in general. That avoids sending an
                    * unrecognized_name when a server is configured for purely
                    * anonymous operation.
                    */
                    if (!cert_chains.empty)
                        send_alert(TLS_Alert(TLS_Alert.UNRECOGNIZED_NAME));
                }
                                
                state.server_hello(
                    new Server_Hello(    state.handshake_io(),
                                        state.hash(),
                                        m_policy,
                                        make_hello_random(rng()), // new session ID
                                        state._version(),
                                        choose_ciphersuite(m_policy,
                                                              state._version(),
                                                               m_creds,
                                                               cert_chains,
                                                              state.client_hello()),
                                        choose_compression(m_policy, state.client_hello().compression_methods()),
                                        state.client_hello().fragment_size(),
                                        state.client_hello().secure_renegotiation(),
                                        secure_renegotiation_data_for_server_hello(),
                                        state.client_hello().supports_session_ticket() && have_session_ticket_key,
                                        state.client_hello().next_protocol_notification(),
                                        m_possible_protocols,
                                        state.client_hello().supports_heartbeats(),
                                        rng()
                    )
                );
                
                secure_renegotiation_check(state.server_hello());
                
                const string sig_algo = state.ciphersuite().sig_algo();
                const string kex_algo = state.ciphersuite().kex_algo();
                
                if (sig_algo != "")
                {
                    assert(!cert_chains[sig_algo].empty,
                    "Attempting to send empty certificate chain");
                    
                    state.server_certs(
                        new Certificate(state.handshake_io(),
                                    state.hash(),
                                    cert_chains[sig_algo])
                    );
                }
                
                Private_Key priv_key = null;
                
                if (kex_algo == "RSA" || sig_algo != "")
                {
                    priv_key = m_creds.private_key_for(    state.server_certs().cert_chain()[0],
                                                            "tls-server",
                                                            sni_hostname
                    );
                    
                    if (!priv_key)
                        throw new Internal_Error("No private key located for associated server cert");
                }
                
                if (kex_algo == "RSA")
                {
                    state.server_rsa_kex_key = priv_key;
                }
                else
                {
                    state.server_kex(
                        new Server_Key_Exchange(state.handshake_io(),
                                                state,
                                                m_policy,
                                                m_creds,
                                                rng(),
                                                priv_key)
                        );
                }
                
                auto trusted_CAs = m_creds.trusted_certificate_authorities("tls-server", sni_hostname);
                
                Vector!X509_DN client_auth_CAs;
                
                foreach (store; trusted_CAs)
                {
                    auto subjects = store.all_subjects();
                    client_auth_CAs.insert(client_auth_CAs.end(),
                                           subjects.ptr,
                                           subjects.end());
                }
                
                if (!client_auth_CAs.empty && state.ciphersuite().sig_algo() != "")
                {
                    state.cert_req(new Certificate_Req(state.handshake_io(),
                                                       state.hash(),
                                                       m_policy,
                                                       client_auth_CAs,
                                                       state._version()));
                    
                    state.set_expected_next(CERTIFICATE);
                }
                
                /*
                * If the client doesn't have a cert they want to use they are
                * allowed to send either an empty cert message or proceed
                * directly to the client key exchange, so allow either case.
                */
                state.set_expected_next(CLIENT_KEX);
                
                state.server_hello_done(
                    new Server_Hello_Done(state.handshake_io(), state.hash())
                );
            }
        }
        else if (type == CERTIFICATE)
        {
            state.client_certs(new Certificate(contents));
            
            state.set_expected_next(CLIENT_KEX);
        }
        else if (type == CLIENT_KEX)
        {
            if (state.received_handshake_msg(CERTIFICATE) && !state.client_certs().empty)
                state.set_expected_next(CERTIFICATE_VERIFY);
            else
                state.set_expected_next(HANDSHAKE_CCS);
            
            state.client_kex(
                new Client_Key_Exchange(contents, state, state.server_rsa_kex_key, m_creds, m_policy, rng())
            );
            
            state.compute_session_keys();
        }
        else if (type == CERTIFICATE_VERIFY)
        {
            state.client_verify(new Certificate_Verify(contents, state._version()));
            
            const Vector!X509_Certificate client_certs = state.client_certs().cert_chain();
            
            const bool sig_valid = state.client_verify().verify(client_certs[0], state);
            
            state.hash().update(state.handshake_io().format(contents, type));
            
            /*
            * Using DECRYPT_ERROR looks weird here, but per RFC 4346 is for
            * "A handshake cryptographic operation failed, including being
            * unable to correctly verify a signature, ..."
            */
            if (!sig_valid)
                throw new TLS_Exception(TLS_Alert.DECRYPT_ERROR, "TLS_Client cert verify failed");
            
            try
            {
                m_creds.verify_certificate_chain("tls-server", "", client_certs);
            }
            catch(Exception e)
            {
                throw new TLS_Exception(TLS_Alert.BAD_CERTIFICATE, e.msg);
            }
            
            state.set_expected_next(HANDSHAKE_CCS);
        }
        else if (type == HANDSHAKE_CCS)
        {
            if (state.server_hello().next_protocol_notification())
                state.set_expected_next(NEXT_PROTOCOL);
            else
                state.set_expected_next(FINISHED);
            
            change_cipher_spec_reader(SERVER);
        }
        else if (type == NEXT_PROTOCOL)
        {
            state.set_expected_next(FINISHED);
            
            state.next_protocol(new Next_Protocol(contents));
            
            // should this be a callback?
            m_next_protocol = state.next_protocol().protocol();
        }
        else if (type == FINISHED)
        {
            state.set_expected_next(HANDSHAKE_NONE);
            
            state.client_finished(new Finished(contents));
            
            if (!state.client_finished().verify(state, CLIENT))
                throw new TLS_Exception(TLS_Alert.DECRYPT_ERROR, "Finished message didn't verify");
            
            if (!state.server_finished())
            {
                // already sent finished if resuming, so this is a new session
                
                state.hash().update(state.handshake_io().format(contents, type));
                
                TLS_Session session_info = TLS_Session(
                        state.server_hello().session_id(),
                        state.session_keys().master_secret(),
                        state.server_hello()._version(),
                        state.server_hello().ciphersuite(),
                        state.server_hello().compression_method(),
                        SERVER,
                        state.server_hello().fragment_size(),
                        get_peer_cert_chain(state),
                        Vector!ubyte(),
                        TLS_Server_Information(state.client_hello().sni_hostname()),
                        state.srp_identifier()
                    );
                
                if (save_session(session_info))
                {
                    if (state.server_hello().supports_session_ticket())
                    {
                        try
                        {
                            const SymmetricKey ticket_key = m_creds.psk("tls-server", "session-ticket", "");
                            
                            state.new_session_ticket(
                                new New_Session_Ticket(state.handshake_io(),
                                                   state.hash(),
                                                   session_info.encrypt(ticket_key, rng()),
                                                   m_policy.session_ticket_lifetime())
                                );
                        }
                        catch {}
                    }
                    else
                        session_manager().save(session_info);
                }
                
                if (!state.new_session_ticket() &&
                    state.server_hello().supports_session_ticket())
                {
                    state.new_session_ticket(
                        new New_Session_Ticket(state.handshake_io(), state.hash())
                        );
                }
                
                state.handshake_io().send(scoped!Change_Cipher_Spec());
                
                change_cipher_spec_writer(SERVER);
                
                state.server_finished(
                    new Finished(state.handshake_io(), state, SERVER)
                );
            }
            activate_session();
        }
        else
            throw new Unexpected_Message("Unknown handshake message received");
    }

    override Handshake_State new_handshake_state(Handshake_IO io)
    {
        Handshake_State state = new Server_Handshake_State(io);
        state.set_expected_next(CLIENT_HELLO);
        return state;
    }

    const TLS_Policy m_policy;
    TLS_Credentials_Manager m_creds;

    Vector!string m_possible_protocols;
    string m_next_protocol;
}

private:

bool check_for_resume(TLS_Session session_info,
                      TLS_Session_Manager session_manager,
                      TLS_Credentials_Manager credentials,
                      in Client_Hello client_hello,
                      Duration session_ticket_lifetime)
{
    const Vector!ubyte client_session_id = client_hello.session_id();
    const Vector!ubyte session_ticket = client_hello.session_ticket();
    
    if (session_ticket.empty)
    {
        if (client_session_id.empty) // not resuming
            return false;
        
        // not found
        if (!session_manager.load_from_session_id(client_session_id, session_info))
            return false;
    }
    else
    {
        // If a session ticket was sent, ignore client session ID
        try
        {
            session_info = TLS_Session.decrypt(
                session_ticket,
                credentials.psk("tls-server", "session-ticket", ""));
            
            if (session_ticket_lifetime != Duration.init &&
                session_info.session_age() > session_ticket_lifetime)
                return false; // ticket has expired
        }
        catch
        {
            return false;
        }
    }
    
    // wrong version
    if (client_hello._version() != session_info._version())
        return false;
    
    // client didn't send original ciphersuite
    if (!value_exists(client_hello.ciphersuites(),
                      session_info.ciphersuite_code()))
        return false;
    
    // client didn't send original compression method
    if (!value_exists(client_hello.compression_methods(),
                      session_info.compression_method()))
        return false;
    
    // client sent a different SRP identity
    if (client_hello.srp_identifier() != "")
    {
        if (client_hello.srp_identifier() != session_info.srp_identifier())
            return false;
    }
    
    // client sent a different SNI hostname
    if (client_hello.sni_hostname() != "")
    {
        if (client_hello.sni_hostname() != session_info.server_info().hostname())
            return false;
    }
    
    return true;
}

/*
* Choose which ciphersuite to use
*/
ushort choose_ciphersuite(in TLS_Policy policy,
                          TLS_Protocol_Version _version,
                          TLS_Credentials_Manager creds,
                          in HashMap!(string, Vector!X509_Certificate) cert_chains,
                          in Client_Hello client_hello)
{
    const bool our_choice = policy.server_uses_own_ciphersuite_preferences();
    
    const bool have_srp = creds.attempt_srp("tls-server", client_hello.sni_hostname());
    
    const Vector!ushort client_suites = client_hello.ciphersuites();
    
    const Vector!ushort server_suites = policy.ciphersuite_list(_version, have_srp);
    
    if (server_suites.empty)
        throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE, "TLS_Policy forbids us from negotiating any ciphersuite");
    
    const bool have_shared_ecc_curve = (policy.choose_curve(client_hello.supported_ecc_curves()) != "");
    
    Vector!ushort pref_list = server_suites;
    Vector!ushort other_list = client_suites;
    
    if (!our_choice)
        std.algorithm.swap(pref_list, other_list);
    
    foreach (suite_id; pref_list)
    {
        if (!value_exists(other_list, suite_id))
            continue;
        
        Ciphersuite suite = Ciphersuite.by_id(suite_id);
        
        if (!have_shared_ecc_curve && suite.ecc_ciphersuite())
            continue;
        
        if (suite.sig_algo() != "" && cert_chains.count(suite.sig_algo()) == 0)
            continue;
        
        /*
        The client may offer SRP cipher suites in the hello message but
        omit the SRP extension.  If the server would like to select an
        SRP cipher suite in this case, the server SHOULD return a fatal
        "unknown_psk_identity" alert immediately after processing the
        client hello message.
         - RFC 5054 section 2.5.1.2
        */
        if (suite.kex_algo() == "SRP_SHA" && client_hello.srp_identifier() == "")
            throw new TLS_Exception(TLS_Alert.UNKNOWN_PSK_IDENTITY,
                                    "TLS_Client wanted SRP but did not send username");
        
        return suite_id;
    }
    
    throw new TLS_Exception(TLS_Alert.HANDSHAKE_FAILURE, "Can't agree on a ciphersuite with client");
}

/*
* Choose which compression algorithm to use
*/
ubyte choose_compression(in TLS_Policy policy, in Vector!ubyte c_comp)
{
    Vector!ubyte s_comp = policy.compression();
    
    for (size_t i = 0; i != s_comp.length; ++i)
        for (size_t j = 0; j != c_comp.length; ++j)
            if (s_comp[i] == c_comp[j])
                return s_comp[i];
    
    return NO_COMPRESSION;
}

HashMap!(string, Vector!X509_Certificate) 
    get_server_certs(in string hostname, TLS_Credentials_Manager creds)
{
    string[] cert_types = [ "RSA", "DSA", "ECDSA", null ];
    
    HashMap!(string, Vector!X509_Certificate) cert_chains;
    
    for (size_t i = 0; cert_types[i]; ++i)
    {
        Vector!X509_Certificate certs =    creds.cert_chain_single_type(cert_types[i], "tls-server", hostname);
        
        if (!certs.empty)
            cert_chains[cert_types[i]] = certs;
    }
    
    return cert_chains;
}

private final class Server_Handshake_State : Handshake_State
{
public:    
    this(Handshake_IO io)
    {
        super(io);
    }
    
    // Used by the server only, in case of RSA key exchange. Not owned
    Private_Key server_rsa_kex_key = null;
    
    /*
    * Used by the server to know if resumption should be allowed on
    * a server-initiated renegotiation
    */
    bool allow_session_resumption = true;
}