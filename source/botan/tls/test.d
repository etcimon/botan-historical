module botan.tls.test;
import botan.constants;
static if (BOTAN_TEST && BOTAN_HAS_TLS):

import botan.rng.auto_rng;
import botan.tls.server;
import botan.tls.client;
import botan.cert.x509.pkcs10;
import botan.cert.x509.x509self;
import botan.cert.x509.x509_ca;
import botan.pubkey.algo.rsa;
import botan.codec.hex;
import botan.utils.memory.memory;
import botan.utils.types;

class TLSCredentialsManagerTest : TLSCredentialsManager
{
public:
    this(in X509Certificate server_cert, in X509Certificate ca_cert, PrivateKey server_key) 
    {
        m_server_cert = server_cert;
        m_ca_cert = ca_cert;
        m_key = server_key;
        auto store = new CertificateStoreInMemory;
        store.addCertificate(m_ca_cert);
        m_stores.pushBack(store);
    }
    
    override Vector!CertificateStore trustedCertificateAuthorities(string, string)
    {
        return m_stores;
    }
    
    override Vector!X509Certificate certChain( in Vector!string cert_key_types, string type, string) 
    {
        Vector!X509Certificate chain;
        
        if (type == "tls-server")
        {
            bool have_match = false;
            foreach (cert_key_type; cert_key_types[])
                if (cert_key_type == m_key.algoName)
                    have_match = true;
            
            if (have_match)
            {
                chain.pushBack(m_server_cert);
                chain.pushBack(m_ca_cert);
            }
        }
        
        return chain;
    }
    
    override void verifyCertificateChain(string type, string purported_hostname, in Vector!X509Certificate cert_chain)
    {
        try
        {
            super.verifyCertificateChain(type, purported_hostname, cert_chain);
        }
        catch(Exception e)
        {
            writeln("Certificate verification failed - " ~ e.msg ~ " - but will ignore");
        }
    }
    
    override PrivateKey privateKeyFor(in X509Certificate, string, string)
    {
        return m_key;
    }
public:
    X509Certificate m_server_cert, m_ca_cert;
    PrivateKey m_key;
    Vector!CertificateStore m_stores;
}

TLSCredentialsManager createCreds(RandomNumberGenerator rng)
{
    PrivateKey ca_key = new RSAPrivateKey(rng, 1024);
    
    X509_Cert_Options ca_opts;
    ca_opts.common_name = "Test CA";
    ca_opts.country = "US";
    ca_opts.cAKey(1);
    
    X509Certificate ca_cert = x509self.createSelfSignedCert(ca_opts, ca_key, "SHA-256", rng);
    
    PrivateKey server_key = new RSAPrivateKey(rng, 1024);
    
    X509_Cert_Options server_opts;
    server_opts.common_name = "localhost";
    server_opts.country = "US";
    
    PKCS10Request req = x509self.createCertReq(server_opts, server_key, "SHA-256", rng);
    
    X509_CA ca = X509_CA(ca_cert, ca_key, "SHA-256");
    
    auto now = Clock.currTime(UTC());
    X509Time start_time = X509Time(now);
    X509Time end_time = X509Time(now + 1.years);
    
    X509Certificate server_cert = ca.signRequest(req, rng, start_time, end_time);
    
    return new TLSCredentialsManagerTest(server_cert, ca_cert, server_key);
}

size_t basicTestHandshake(RandomNumberGenerator rng,
                            TLSProtocolVersion offer_version,
                            TLSCredentialsManager creds,
                            TLSPolicy policy)
{
    auto server_sessions = scoped!TLSSessionManagerInMemory(rng);
    auto client_sessions = scoped!TLSSessionManagerInMemory(rng);
    
    Vector!ubyte c2s_q, s2c_q, c2s_data, s2c_data;
    
    auto handshake_complete = (in TLSSession session) {
        if (session.Version() != offer_version)
            writeln("Wrong version negotiated");
        return true;
    };
    
    auto print_alert = (TLSAlert alert, in ubyte[])
    {
        if (alert.isValid())
            writeln("TLSServer recvd alert " ~ alert.typeString());
    };
    
    auto save_server_data = (in ubyte[] buf) {
        c2s_data.insert(buf);
    };
    
    auto save_client_data = (in ubyte[] buf) {
        s2c_data.insert(buf);
    };
    
    auto server = scoped!TLSServer((in ubyte[] buf) { s2c_q.insert(buf); },
                                save_server_data,
                                print_alert,
                                handshake_complete,
                                server_sessions,
                                creds,
                                policy,
                                rng,
                                ["test/1", "test/2"]);
    
    auto next_protocol_chooser = (Vector!string protos) {
        if (protos.length != 2)
            writeln("Bad protocol size");
        if (protos[0] != "test/1" || protos[1] != "test/2")
            writeln("Bad protocol values");
        return "test/3";
    };
    
    auto client = scoped!TLSClient((in ubyte[] buf) { c2s_q.insert(buf); },
                                    save_client_data,
                                    print_alert,
                                    handshake_complete,
                                    client_sessions,
                                    creds,
                                    policy,
                                    rng,
                                    TLSServerInformation(),
                                    offer_version,
                                    next_protocol_chooser);
    
    while(true)
    {
        if (client.isActive())
            client.send("1");
        if (server.isActive())
        {
            if (server.nextProtocol() != "test/3")
                writeln("Wrong protocol " ~ server.nextProtocol());
            server.send("2");
        }
        
        /*
        * Use this as a temp value to hold the queues as otherwise they
        * might end up appending more in response to messages during the
        * handshake.
        */
        Vector!ubyte input;
        swap(c2s_q, input);
        
        try
        {
            server.receivedData(&input[0], input.length);
        }
        catch(Exception e)
        {
            writeln("TLSServer error - " ~ e.msg);
            break;
        }
        
        input.clear();
        swap(s2c_q, input);
        
        try
        {
            client.receivedData(&input[0], input.length);
        }
        catch(Exception e)
        {
            writeln("TLSClient error - " ~ e.msg);
            break;
        }
        
        if (c2s_data.length)
        {
            if (c2s_data[0] != '1')
            {
                writeln("Error");
                return 1;
            }
        }
        
        if (s2c_data.length)
        {
            if (s2c_data[0] != '2')
            {
                writeln("Error");
                return 1;
            }
        }
        
        if (s2c_data.length && c2s_data.length)
            break;
    }
    
    return 0;
}

class TestPolicy : TLSPolicy
{
public:
    bool acceptableProtocolVersion(TLSProtocolVersion) const { return true; }
}

unittest
{
    size_t errors = 0;
    
    Test_Policy default_policy;
    AutoSeededRNG rng;
    TLSCredentialsManager basic_creds = createCreds(rng);
    
    errors += basicTestHandshake(rng, TLSProtocolVersion.SSL_V3, basic_creds, default_policy);
    errors += basicTestHandshake(rng, TLSProtocolVersion.TLS_V10, basic_creds, default_policy);
    errors += basicTestHandshake(rng, TLSProtocolVersion.TLS_V11, basic_creds, default_policy);
    errors += basicTestHandshake(rng, TLSProtocolVersion.TLS_V12, basic_creds, default_policy);
    
    testReport("TLS", 4, errors);

}