/*
* TLS Handshake State
* (C) 2004-2006,2011,2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_handshake_state;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.tls.tls_handshake_hash;
import botan.tls.tls_handshake_io;
import botan.tls.tls_session_key;
import botan.tls.tls_ciphersuite;
import botan.tls.tls_exceptn;
import botan.tls.tls_handshake_msg;
import botan.pubkey.pk_keys;
import botan.pubkey.pubkey;
import botan.kdf.kdf;
import botan.tls.tls_messages;
import botan.tls.tls_record;
import functional;

package:
/**
* SSL/TLS Handshake State
*/
class Handshake_State
{
public:
    /*
    * Initialize the SSL/TLS Handshake State
    */
    this(Handshake_IO io, void delegate(in Handshake_Message) msg_callback = null) 
    {
        m_msg_callback = msg_callback;
        m_handshake_io = io;
        m_version = m_handshake_io.initial_record_version();
    }

    ~this() {}

    Handshake_IO handshake_io() { return *m_handshake_io; }

    /**
    * Return true iff we have received a particular message already
    * @param msg_type = the message type
    */
    bool received_handshake_msg(Handshake_Type handshake_msg) const
    {
        const uint mask = bitmask_for_handshake_type(handshake_msg);
        
        return (m_hand_received_mask & mask);
    }

    /**
    * Confirm that we were expecting this message type
    * @param msg_type = the message type
    */
    void confirm_transition_to(Handshake_Type handshake_msg)
    {
        const uint mask = bitmask_for_handshake_type(handshake_msg);
        
        m_hand_received_mask |= mask;
        
        const bool ok = (m_hand_expecting_mask & mask); // overlap?
        
        if (!ok)
            throw new TLS_Unexpected_Message("Unexpected state transition in handshake, got " ~
                                         to!string(handshake_msg) ~
                                         " expected " ~ to!string(m_hand_expecting_mask) ~
                                         " received " ~ to!string(m_hand_received_mask));
        
        /* We don't know what to expect next, so force a call to
            set_expected_next; if it doesn't happen, the next transition
            check will always fail which is what we want.
        */
        m_hand_expecting_mask = 0;
    }

    /**
    * Record that we are expecting a particular message type next
    * @param msg_type = the message type
    */
    void set_expected_next(Handshake_Type handshake_msg)
    {
        m_hand_expecting_mask |= bitmask_for_handshake_type(handshake_msg);
    }

    Pair!(Handshake_Type, Vector!ubyte) get_next_handshake_msg()
    {
        const bool expecting_ccs = (bitmask_for_handshake_type(HANDSHAKE_CCS) & m_hand_expecting_mask);
        
        return m_handshake_io.get_next_record(expecting_ccs);
    }

    Vector!ubyte session_ticket() const
    {
        if (new_session_ticket() && !new_session_ticket().ticket().empty())
            return new_session_ticket().ticket();
        
        return client_hello().session_ticket();
    }

    Pair!(string, Signature_Format)
        understand_sig_format(in Public_Key key, string hash_algo, string sig_algo, bool for_client_auth) const
    {
        const string algo_name = key.algo_name;
        
        /*
        FIXME: This should check what was sent against the client hello
        preferences, or the certificate request, to ensure it was allowed
        by those restrictions.

        Or not?
        */
        
        if (this._version().supports_negotiable_signature_algorithms())
        {
            if (hash_algo == "")
                throw new Decoding_Error("Counterparty did not send hash/sig IDS");
            
            if (sig_algo != algo_name)
                throw new Decoding_Error("Counterparty sent inconsistent key and sig types");
        }
        else
        {
            if (hash_algo != "" || sig_algo != "")
                throw new Decoding_Error("Counterparty sent hash/sig IDs with old version");
        }
        
        if (algo_name == "RSA")
        {
            if (for_client_auth && this._version() == TLS_Protocol_Version.SSL_V3)
            {
                hash_algo = "Raw";
            }
            else if (!this._version().supports_negotiable_signature_algorithms())
            {
                hash_algo = "Parallel(MD5,SHA-160)";
            }
            
            const string padding = "EMSA3(" ~ hash_algo ~ ")";
            return Pair(padding, IEEE_1363);
        }
        else if (algo_name == "DSA" || algo_name == "ECDSA")
        {
            if (algo_name == "DSA" && for_client_auth && this._version() == TLS_Protocol_Version.SSL_V3)
            {
                hash_algo = "Raw";
            }
            else if (!this._version().supports_negotiable_signature_algorithms())
            {
                hash_algo = "SHA-1";
            }
            
            const string padding = "EMSA1(" ~ hash_algo ~ ")";
            
            return Pair(padding, DER_SEQUENCE);
        }
        
        throw new Invalid_Argument(algo_name ~ " is invalid/unknown for TLS signatures");
    }

    Pair!(string, Signature_Format)
        choose_sig_format(in Private_Key key,
                          ref string hash_algo_out,
                          ref string sig_algo_out,
                          bool for_client_auth,
                          in TLS_Policy policy) const
    {
        const string sig_algo = key.algo_name;
        
        const string hash_algo = choose_hash(sig_algo,
                                             this._version(),
                                             policy,
                                             for_client_auth,
                                             client_hello(),
                                             cert_req());
        
        if (this._version().supports_negotiable_signature_algorithms())
        {
            hash_algo_out = hash_algo;
            sig_algo_out = sig_algo;
        }
        
        if (sig_algo == "RSA")
        {
            const string padding = "EMSA3(" ~ hash_algo ~ ")";
            
            return Pair(padding, IEEE_1363);
        }
        else if (sig_algo == "DSA" || sig_algo == "ECDSA")
        {
            const string padding = "EMSA1(" ~ hash_algo ~ ")";
            
            return Pair(padding, DER_SEQUENCE);
        }
        
        throw new Invalid_Argument(sig_algo ~ " is invalid/unknown for TLS signatures");
    }

    string srp_identifier() const
    {
        if (ciphersuite().valid() && ciphersuite().kex_algo() == "SRP_SHA")
            return client_hello().srp_identifier();
        
        return "";
    }

    KDF protocol_specific_prf() const
    {
        if (_version() == TLS_Protocol_Version.SSL_V3)
        {
            return get_kdf("SSL3-PRF");
        }
        else if (_version().supports_ciphersuite_specific_prf())
        {
            const string prf_algo = ciphersuite().prf_algo();
            
            if (prf_algo == "MD5" || prf_algo == "SHA-1")
                return get_kdf("TLS-12-PRF(SHA-256)");
            
            return get_kdf("TLS-12-PRF(" ~ prf_algo ~ ")");
        }
        else
        {
            // TLS v1.0, v1.1 and DTLS v1.0
            return get_kdf("TLS-PRF");
        }
        
        throw new Internal_Error("Unknown version code " ~ _version().toString());
    }

    TLS_Protocol_Version _version() const { return m_version; }

    void set_version(in TLS_Protocol_Version _version)
    {
        m_version = _version;
    }

    void hello_verify_request(in Hello_Verify_Request hello_verify)
    {
        note_message(hello_verify);
        
        m_client_hello.update_hello_cookie(hello_verify);
        hash().clear();
        hash().update(handshake_io().send(*m_client_hello));
        note_message(*m_client_hello);
    }


    void client_hello(Client_Hello client_hello)
    {
        m_client_hello = client_hello;
        note_message(*m_client_hello);
    }
    
    void server_hello(Server_Hello server_hello)
    {
        m_server_hello = server_hello;
        m_ciphersuite = TLS_Ciphersuite.by_id(m_server_hello.ciphersuite());
        note_message(*m_server_hello);
    }
    
    void server_certs(Certificate server_certs)
    {
        m_server_certs = server_certs;
        note_message(*m_server_certs);
    }
    
    void server_kex(Server_Key_Exchange server_kex)
    {
        m_server_kex = server_kex;
        note_message(*m_server_kex);
    }
    
    void cert_req(Certificate_Req cert_req)
    {
        m_cert_req = cert_req;
        note_message(*m_cert_req);
    }

    void server_hello_done(Server_Hello_Done server_hello_done)
    {
        m_server_hello_done = server_hello_done;
        note_message(*m_server_hello_done);
    }
    
    void client_certs(Certificate client_certs)
    {
        m_client_certs = client_certs;
        note_message(*m_client_certs);
    }
    
    void client_kex(Client_Key_Exchange client_kex)
    {
        m_client_kex = client_kex;
        note_message(*m_client_kex);
    }
    
    void client_verify(Certificate_Verify client_verify)
    {
        m_client_verify.reset(client_verify);
        note_message(*m_client_verify);
    }
    
    void next_protocol(Next_Protocol next_protocol)
    {
        m_next_protocol = next_protocol;
        note_message(*m_next_protocol);
    }

    void new_session_ticket(New_Session_Ticket new_session_ticket)
    {
        m_new_session_ticket = new_session_ticket;
        note_message(*m_new_session_ticket);
    }
    
    void server_finished(Finished server_finished)
    {
        m_server_finished = server_finished;
        note_message(*m_server_finished);
    }
    
    void client_finished(Finished client_finished)
    {
        m_client_finished = client_finished;
        note_message(*m_client_finished);
    }

    Client_Hello client_hello() const
    { return *m_client_hello; }

    Server_Hello server_hello() const
    { return *m_server_hello; }

    Certificate server_certs() const
    { return *m_server_certs; }

    Server_Key_Exchange server_kex() const
    { return *m_server_kex; }

    Certificate_Req cert_req() const
    { return *m_cert_req; }

    Server_Hello_Done server_hello_done() const
    { return *m_server_hello_done; }

    Certificate client_certs() const
    { return *m_client_certs; }

    Client_Key_Exchange client_kex() const
    { return *m_client_kex; }

    Certificate_Verify client_verify() const
    { return *m_client_verify; }

    Next_Protocol next_protocol() const
    { return *m_next_protocol; }

    New_Session_Ticket new_session_ticket() const
    { return *m_new_session_ticket; }

    Finished server_finished() const
    { return *m_server_finished; }

    Finished client_finished() const
    { return *m_client_finished; }

    TLS_Ciphersuite ciphersuite() const { return m_ciphersuite; }

    TLS_Session_Keys session_keys() const { return m_session_keys; }

    void compute_session_keys()
    {
        m_session_keys = TLS_Session_Keys(this, client_kex().pre_master_secret(), false);
    }

    void compute_session_keys(in Secure_Vector!ubyte resume_master_secret)
    {
        m_session_keys = TLS_Session_Keys(this, resume_master_secret, true);
    }

    Handshake_Hash hash() { return m_handshake_hash; }

    Handshake_Hash hash() const { return m_handshake_hash; }

    void note_message(in Handshake_Message msg)
    {
        if (m_msg_callback)
            m_msg_callback(msg);
    }

private:

    void delegate(in Handshake_Message) m_msg_callback;

    Unique!Handshake_IO m_handshake_io;

    uint m_hand_expecting_mask = 0;
    uint m_hand_received_mask = 0;
    TLS_Protocol_Version m_version;
    TLS_Ciphersuite m_ciphersuite;
    TLS_Session_Keys m_session_keys;
    Handshake_Hash m_handshake_hash;

    Unique!Client_Hello m_client_hello;
    Unique!Server_Hello m_server_hello;
    Unique!Certificate m_server_certs;
    Unique!Server_Key_Exchange m_server_kex;
    Unique!Certificate_Req m_cert_req;
    Unique!Server_Hello_Done m_server_hello_done;
    Unique!Certificate m_client_certs;
    Unique!Client_Key_Exchange m_client_kex;
    Unique!Certificate_Verify m_client_verify;
    Unique!Next_Protocol m_next_protocol;
    Unique!New_Session_Ticket m_new_session_ticket;
    Unique!Finished m_server_finished;
    Unique!Finished m_client_finished;
}


private:

uint bitmask_for_handshake_type(Handshake_Type type)
{
    switch(type)
    {
        case HELLO_VERIFY_REQUEST:
            return (1 << 0);
            
        case HELLO_REQUEST:
            return (1 << 1);
            
            /*
        * Same code point for both client hello styles
        */
        case CLIENT_HELLO:
        case CLIENT_HELLO_SSLV2:
            return (1 << 2);
            
        case SERVER_HELLO:
            return (1 << 3);
            
        case CERTIFICATE:
            return (1 << 4);
            
        case CERTIFICATE_URL:
            return (1 << 5);
            
        case CERTIFICATE_STATUS:
            return (1 << 6);
            
        case SERVER_KEX:
            return (1 << 7);
            
        case CERTIFICATE_REQUEST:
            return (1 << 8);
            
        case SERVER_HELLO_DONE:
            return (1 << 9);
            
        case CERTIFICATE_VERIFY:
            return (1 << 10);
            
        case CLIENT_KEX:
            return (1 << 11);
            
        case NEXT_PROTOCOL:
            return (1 << 12);
            
        case NEW_SESSION_TICKET:
            return (1 << 13);
            
        case HANDSHAKE_CCS:
            return (1 << 14);
            
        case FINISHED:
            return (1 << 15);
            
            // allow explicitly disabling new handshakes
        case HANDSHAKE_NONE:
            return 0;
    }
    
    throw new Internal_Error("Unknown handshake type " ~ to!string(type));
}



string choose_hash(in string sig_algo,
                   TLS_Protocol_Version negotiated_version,
                   in TLS_Policy policy,
                   bool for_client_auth,
                   in Client_Hello client_hello,
                   in Certificate_Req cert_req)
{
    if (!negotiated_version.supports_negotiable_signature_algorithms())
    {
        if (for_client_auth && negotiated_version == TLS_Protocol_Version.SSL_V3)
            return "Raw";
        
        if (sig_algo == "RSA")
            return "Parallel(MD5,SHA-160)";
        
        if (sig_algo == "DSA")
            return "SHA-1";
        
        if (sig_algo == "ECDSA")
            return "SHA-1";
        
        throw new Internal_Error("Unknown TLS signature algo " ~ sig_algo);
    }
    
    const Vector!(Pair!(string, string)) supported_algos = for_client_auth ?
        cert_req.supported_algos() :
            client_hello.supported_algos();
    
    if (!supported_algos.empty())
    {
        const Vector!string hashes = policy.allowed_signature_hashes();
        
        /*
        * Choose our most preferred hash that the counterparty supports
        * in pairing with the signature algorithm we want to use.
        */
        foreach (hash; hashes)
        {
            foreach (algo; supported_algos)
            {
                if (algo.first == hash && algo.second == sig_algo)
                    return hash;
            }
        }
    }
    
    // TLS v1.2 default hash if the counterparty sent nothing
    return "SHA-1";
}
