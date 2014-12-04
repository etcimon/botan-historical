/*
* TLS Messages
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.messages;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.tls.handshake_state;
import botan.tls.session_key;
import botan.utils.containers.multimap;

public import botan.algo_base.sym_algo;
public import botan.tls.tls_handshake_msg;
public import botan.tls.session;
public import botan.tls.policy;
public import botan.tls.ciphersuite;
public import botan.tls.reader;
public import botan.tls.extensions;
public import botan.tls.handshake_io;
public import botan.tls.version_;
public import botan.tls.handshake_hash;
public import botan.tls.magic;
public import botan.credentials.credentials_manager;
import botan.constructs.srp6;
import botan.utils.loadstor;
import botan.constructs.srp6;
import botan.math.bigint.bigint;
import botan.pubkey.pkcs8;
import botan.pubkey.pubkey;
import botan.pubkey.algo.dh;
import botan.pubkey.algo.ecdh;
import botan.pubkey.algo.rsa;
import botan.cert.x509.x509cert;
import botan.asn1.oids;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.loadstor;
import botan.utils.types;
import botan.libstate.lookup;
import botan.rng.rng;
import botan.utils.types : Unique;
import std.datetime;
import botan.utils.types;
// import string;

enum {
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV          = 0x00FF
}

/**
* TLS Handshake Message Base Class
*/
class HandshakeMessage
{
public:
    abstract HandshakeType type() const;
    
    abstract Vector!ubyte serialize() const;
    
    ~this() {}
}

/**
* DTLS Hello Verify Request
*/
final class HelloVerifyRequest : HandshakeMessage
{
public:
    override Vector!ubyte serialize() const
    {
        /* DTLS 1.2 server implementations SHOULD use DTLS version 1.0
            regardless of the version of TLS that is expected to be
            negotiated (RFC 6347, section 4.2.1)
        */
            
        TLSProtocolVersion format_version = TLSProtocolVersion(TLSProtocolVersion.DTLSV10);
        
        Vector!ubyte bits;
		bits.pushBack(format_version.majorVersion());
		bits.pushBack(format_version.minorVersion());
        bits.pushBack(cast(ubyte) m_cookie.length);
        bits ~= m_cookie;
        return bits;
    }

    override HandshakeType type() const { return HELLO_VERIFY_REQUEST; }

    Vector!ubyte cookie() const { return m_cookie; }

    this(in Vector!ubyte buf)
    {
        if (buf.length < 3)
            throw new DecodingError("Hello verify request too small");
        
        TLSProtocolVersion version_ = TLSProtocolVersion(buf[0], buf[1]);
        
        if (version_ != TLSProtocolVersion.DTLS_V10 &&
            version_ != TLSProtocolVersion.DTLS_V12)
        {
            throw new DecodingError("Unknown version from server in hello verify request");
        }

        if ((cast(size_t) buf[2]) + 3 != buf.length)
            throw new DecodingError("Bad length in hello verify request");
        
        m_cookie.replace(buf.ptr[3 .. buf.length]);
    }

    this(in Vector!ubyte client_hello_bits, in string client_identity, in SymmetricKey secret_key)
    {
        Unique!MessageAuthenticationCode hmac = getMac("HMAC(SHA-256)");
        hmac.setKey(secret_key);
        
        hmac.updateBigEndian(client_hello_bits.length);
        hmac.update(client_hello_bits);
        hmac.updateBigEndian(client_identity.length);
        hmac.update(client_identity);
        
        m_cookie = unlock(hmac.finished());
    }
private:
    Vector!ubyte m_cookie;
}

/**
* TLSClient Hello Message
*/
final class ClientHello : HandshakeMessage
{
public:
    override HandshakeType type() const { return CLIENT_HELLO; }

    TLSProtocolVersion Version() const { return m_version; }

    Vector!ubyte random() const { return m_random; }

    Vector!ubyte sessionId() const { return m_session_id; }

    Vector!ushort ciphersuites() const { return m_suites; }

    Vector!ubyte compressionMethods() const { return m_comp_methods; }

    /*
    * Check if we offered this ciphersuite
    */
    bool offeredSuite(ushort ciphersuite) const
    {
        for (size_t i = 0; i != m_suites.length; ++i)
            if (m_suites[i] == ciphersuite)
                return true;
        return false;
    }

    Vector!( Pair!(string, string) ) supportedAlgos() const
    {
        if (SignatureAlgorithms sigs = m_extensions.get!SignatureAlgorithms())
            return sigs.supportedSignatureAlgorthms();
        return Vector!( Pair!(string, string) )();
    }

    Vector!string supportedEccCurves() const
    {
        if (SupportedEllipticCurves ecc = m_extensions.get!SupportedEllipticCurves())
            return ecc.curves();
        return Vector!string();
    }

    string sniHostname() const
    {
        if (ServerNameIndicator sni = m_extensions.get!ServerNameIndicator())
            return sni.hostName();
        return "";
    }

    string srpIdentifier() const
    {
        if (SRPIdentifier srp = m_extensions.get!SRPIdentifier())
            return srp.identifier();
        return "";
    }

    bool secureRenegotiation() const
    {
        return m_extensions.get!RenegotiationExtension();
    }

    Vector!ubyte renegotiationInfo() const
    {
        if (RenegotiationExtension reneg = m_extensions.get!RenegotiationExtension())
            return reneg.renegotiationInfo();
        return Vector!ubyte();
    }

    bool nextProtocolNotification() const
    {
        return m_extensions.get!NextProtocolNotification();
    }

    size_t fragmentSize() const
    {
        if (MaximumFragmentLength frag = m_extensions.get!MaximumFragmentLength())
            return frag.fragmentSize();
        return 0;
    }

    bool supportsSessionTicket() const
    {
        return m_extensions.get!SessionTicket();
    }

    Vector!ubyte sessionTicket() const
    {
        if (SessionTicket ticket = m_extensions.get!SessionTicket())
            return ticket.contents();
        return Vector!ubyte();
    }

    bool supportsHeartbeats() const
    {
        return m_extensions.get!HeartbeatSupportIndicator();
    }

    bool peerCanSendHeartbeats() const
    {
        if (HeartbeatSupportIndicator hb = m_extensions.get!HeartbeatSupportIndicator())
            return hb.peerAllowedToSend();
        return false;
    }

    void updateHelloCookie(in HelloVerifyRequest hello_verify)
    {
        if (!m_version.isDatagramProtocol())
            throw new Exception("Cannot use hello cookie with stream protocol");
        
        m_hello_cookie = hello_verify.cookie();
    }

    HandshakeExtensionType[] extensionTypes() const
    { return m_extensions.extensionTypes(); }

    /*
    * Create a new TLSClient Hello message
    */
    this(HandshakeIO io,
         HandshakeHash hash,
         TLSProtocolVersion _version,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         in Vector!ubyte reneg_info,
         bool next_protocol,
         in string hostname,
         in string srp_identifier) 
    {
        m_version = _version;
        m_random = makeHelloRandom(rng);
        m_suites = policy.ciphersuiteList(m_version, (srp_identifier != ""));
        m_comp_methods = policy.compression();
        m_extensions.add(new RenegotiationExtension(reneg_info));
        m_extensions.add(new SRPIdentifier(srp_identifier));
        m_extensions.add(new ServerNameIndicator(hostname));
        m_extensions.add(new SessionTicket());
        m_extensions.add(new SupportedEllipticCurves(policy.allowedEccCurves()));
        
        if (policy.negotiateHeartbeatSupport())
            m_extensions.add(new HeartbeatSupportIndicator(true));
        
        if (m_version.supportsNegotiableSignatureAlgorithms())
            m_extensions.add(new SignatureAlgorithms(policy.allowedSignatureHashes(),
                                                      policy.allowedSignatureMethods()));
        
        if (reneg_info.empty && next_protocol)
            m_extensions.add(new NextProtocolNotification());
        
        hash.update(io.send(this));
    }


    /*
    * Create a new TLSClient Hello message (session resumption case)
    */
    this(HandshakeIO io,
         HandshakeHash hash,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         in Vector!ubyte reneg_info,
         const TLSSession session,
         bool next_protocol = false)
    { 
        m_version = session.Version();
        m_session_id = session.sessionId();
        m_random = makeHelloRandom(rng);
        m_suites = policy.ciphersuiteList(m_version, (session.srpIdentifier() != ""));
        m_comp_methods = policy.compression();
        if (!valueExists(m_suites, session.ciphersuiteCode()))
            m_suites.pushBack(session.ciphersuiteCode());
        
        if (!valueExists(m_comp_methods, session.compressionMethod()))
            m_comp_methods.pushBack(session.compressionMethod());
        
        m_extensions.add(new RenegotiationExtension(reneg_info));
        m_extensions.add(new SRPIdentifier(session.srpIdentifier()));
        m_extensions.add(new ServerNameIndicator(session.serverInfo().hostname()));
        m_extensions.add(new SessionTicket(session.sessionTicket()));
        m_extensions.add(new SupportedEllipticCurves(policy.allowedEccCurves()));
        
        if (policy.negotiateHeartbeatSupport())
            m_extensions.add(new HeartbeatSupportIndicator(true));
        
        if (session.fragmentSize() != 0)
            m_extensions.add(new MaximumFragmentLength(session.fragmentSize()));
        
        if (m_version.supportsNegotiableSignatureAlgorithms())
            m_extensions.add(new SignatureAlgorithms(policy.allowedSignatureHashes(),
                                                      policy.allowedSignatureMethods()));
        
        if (reneg_info.empty && next_protocol)
            m_extensions.add(new NextProtocolNotification());
        
        hash.update(io.send(this));
    }

    /*
    * Read a counterparty client hello
    */
    this(in Vector!ubyte buf, HandshakeType type)
    {
        if (type == CLIENT_HELLO)
            deserialize(buf);
        else
            deserialize_sslv2(buf);
    }

private:
    /*
    * Serialize a TLSClient Hello message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        
        buf.pushBack(m_version.majorVersion());
        buf.pushBack(m_version.minorVersion());
        buf ~= m_random;
        
        appendTlsLengthValue(buf, m_session_id, 1);
        
        if (m_version.isDatagramProtocol())
            appendTlsLengthValue(buf, m_hello_cookie, 1);
        
        appendTlsLengthValue(buf, m_suites, 2);
        appendTlsLengthValue(buf, m_comp_methods, 1);
        
        /*
        * May not want to send extensions at all in some cases. If so,
        * should include SCSV value (if reneg info is empty, if not we are
        * renegotiating with a modern server)
        */
        
        buf += m_extensions.serialize();
        
        return buf;
    }

    /*
    * Deserialize a TLSClient Hello message
    */
    void deserialize(in Vector!ubyte buf)
    {
        if (buf.length == 0)
            throw new DecodingError("ClientHello: Packet corrupted");
        
        if (buf.length < 41)
            throw new DecodingError("ClientHello: Packet corrupted");
        
        TLSDataReader reader = TLSDataReader("ClientHello", buf);
        
        const ubyte major_version = reader.get_byte();
        const ubyte minor_version = reader.get_byte();
        
        m_version = TLSProtocolVersion(major_version, minor_version);
        
        m_random = reader.get_fixed!ubyte(32);
        
        if (m_version.isDatagramProtocol())
            m_hello_cookie = reader.getRange!ubyte(1, 0, 255);
        
        m_session_id = reader.getRange!ubyte(1, 0, 32);
        
        m_suites = reader.getRangeVector!ushort(2, 1, 32767);
        
        m_comp_methods = reader.getRangeVector!ubyte(1, 1, 255);
        
        m_extensions.deserialize(reader);
        
        if (offeredSuite(cast(ushort)(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
        {
            if (RenegotiationExtension reneg = m_extensions.get!RenegotiationExtension())
            {
                if (!reneg.renegotiationInfo().empty)
                    throw new TLSException(TLSAlert.HANDSHAKE_FAILURE,
                                            "TLSClient send renegotiation SCSV and non-empty extension");
            }
            else
            {
                // add fake extension
                m_extensions.add(new RenegotiationExtension());
            }
        }
    }

    void deserializeSslv2(in Vector!ubyte buf)
    {
        if (buf.length < 12 || buf[0] != 1)
            throw new DecodingError("ClientHello: SSLv2 hello corrupted");
        
        const size_t cipher_spec_len = make_ushort(buf[3], buf[4]);
        const size_t m_session_id_len = make_ushort(buf[5], buf[6]);
        const size_t challenge_len = make_ushort(buf[7], buf[8]);
        
        const size_t expected_size = (9 + m_session_id_len + cipher_spec_len + challenge_len);
        
        if (buf.length != expected_size)
            throw new DecodingError("ClientHello: SSLv2 hello corrupted");
        
        if (m_session_id_len != 0 || cipher_spec_len % 3 != 0 ||
            (challenge_len < 16 || challenge_len > 32))
        {
            throw new DecodingError("ClientHello: SSLv2 hello corrupted");
        }
        
        m_version = TLSProtocolVersion(buf[1], buf[2]);
        
        for (size_t i = 9; i != 9 + cipher_spec_len; i += 3)
        {
            if (buf[i] != 0) // a SSLv2 cipherspec; ignore it
                continue;
            
            m_suites.pushBack(make_ushort(buf[i+1], buf[i+2]));
        }
        
        m_random.resize(challenge_len);
        copyMem(m_random.ptr, &buf[9+cipher_spec_len+m_session_id_len], challenge_len);
        
        if (offeredSuite(cast(ushort)(TLS_EMPTY_RENEGOTIATION_INFO_SCSV)))
            m_extensions.add(new RenegotiationExtension());
    }

    TLSProtocolVersion m_version;
    Vector!ubyte m_session_id;
    Vector!ubyte m_random;
    Vector!ushort m_suites;
    Vector!ubyte m_comp_methods;
    Vector!ubyte m_hello_cookie; // DTLS only

    TLSExtensions m_extensions;
}

/**
* TLSServer Hello Message
*/
final class ServerHello : HandshakeMessage
{
public:
    override HandshakeType type() const { return SERVER_HELLO; }

    TLSProtocolVersion Version() const { return m_version; }

    Vector!ubyte random() const { return m_random; }

    Vector!ubyte sessionId() const { return m_session_id; }

    ushort ciphersuite() const { return m_ciphersuite; }

    ubyte compressionMethod() const { return m_comp_method; }

    bool secureRenegotiation() const
    {
        return m_extensions.get!RenegotiationExtension();
    }

    Vector!ubyte renegotiationInfo() const
    {
        if (RenegotiationExtension reneg = m_extensions.get!RenegotiationExtension())
            return reneg.renegotiationInfo();
        return Vector!ubyte();
    }

    bool nextProtocolNotification() const
    {
        return m_extensions.get!NextProtocolNotification();
    }

    Vector!string nextProtocols() const
    {
        if (NextProtocolNotification npn = m_extensions.get!NextProtocolNotification())
            return npn.protocols();
        return Vector!string();
    }

    size_t fragmentSize() const
    {
        if (MaximumFragmentLength frag = m_extensions.get!MaximumFragmentLength())
            return frag.fragmentSize();
        return 0;
    }

    bool supportsSessionTicket() const
    {
        return m_extensions.get!SessionTicket();
    }

    bool supportsHeartbeats() const
    {
        return m_extensions.get!HeartbeatSupportIndicator();
    }

    bool peerCanSendHeartbeats() const
    {
        if (HeartbeatSupportIndicator hb = m_extensions.get!HeartbeatSupportIndicator())
            return hb.peerAllowedToSend();
        return false;
    }

    HandshakeExtensionType[] extensionTypes() const
    { return m_extensions.extensionTypes(); }

    /*
    * Create a new TLSServer Hello message
    */
    this(HandshakeIO io,
         HandshakeHash hash,
         in TLSPolicy policy,
         in Vector!ubyte session_id,
         TLSProtocolVersion ver,
         ushort ciphersuite,
         ubyte compression,
         size_t max_fragment_size,
         bool client_has_secure_renegotiation,
         in Vector!ubyte reneg_info,
         bool offer_session_ticket,
         bool client_has_npn,
         const Vector!string next_protocols,
         bool client_has_heartbeat,
         RandomNumberGenerator rng) 
    {
        m_version = ver;
        m_session_id = session_id;
        m_random = makeHelloRandom(rng);
        m_ciphersuite = ciphersuite;
        m_comp_method = compression;
        
        if (client_has_heartbeat && policy.negotiateHeartbeatSupport())
            m_extensions.add(new HeartbeatSupportIndicator(true));
        
        /*
        * Even a client that offered SSLv3 and sent the SCSV will get an
        * extension back. This is probably the right thing to do.
        */
        if (client_has_secure_renegotiation)
            m_extensions.add(new RenegotiationExtension(reneg_info));
        
        if (max_fragment_size)
            m_extensions.add(new MaximumFragmentLength(max_fragment_size));
        
        if (client_has_npn)
            m_extensions.add(new NextProtocolNotification(next_protocols));
        
        if (offer_session_ticket)
            m_extensions.add(new SessionTicket());
        
        hash.update(io.send(this));
    }

    /*
    * Deserialize a TLSServer Hello message
    */
    this(in Vector!ubyte buf)
    {
        if (buf.length < 38)
            throw new DecodingError("ServerHello: Packet corrupted");
        
        TLSDataReader reader = TLSDataReader("ServerHello", buf);
        
        const ubyte major_version = reader.get_byte();
        const ubyte minor_version = reader.get_byte();
        
        m_version = TLSProtocolVersion(major_version, minor_version);
        
        m_random = reader.get_fixed!ubyte(32);
        
        m_session_id = reader.getRange!ubyte(1, 0, 32);
        
        m_ciphersuite = reader.get_ushort();
        
        m_comp_method = reader.get_byte();
        
        m_extensions.deserialize(reader);
    }
private:
    /*
    * Serialize a TLSServer Hello message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        
        buf.pushBack(m_version.majorVersion());
        buf.pushBack(m_version.minorVersion());
        buf += m_random;
        
        appendTlsLengthValue(buf, m_session_id, 1);
        
        buf.pushBack(get_byte(0, m_ciphersuite));
        buf.pushBack(get_byte(1, m_ciphersuite));
        
        buf.pushBack(m_comp_method);
        
        buf += m_extensions.serialize();
        
        return buf;
    }

    TLSProtocolVersion m_version;
    Vector!ubyte m_session_id, m_random;
    ushort m_ciphersuite;
    ubyte m_comp_method;

    TLSExtensions m_extensions;
}

/**
* TLSClient Key Exchange Message
*/
final class ClientKeyExchange : HandshakeMessage
{
public:
    override HandshakeType type() const { return CLIENT_KEX; }

    SecureVector!ubyte preMasterSecret() const
    { return m_pre_master; }

    /*
    * Read a TLSClient Key Exchange message
    */
    this(in Vector!ubyte contents,
         const HandshakeState state,
         const PrivateKey server_rsa_kex_key,
         TLSCredentialsManager creds,
         in TLSPolicy policy,
         RandomNumberGenerator rng)
    {
        const string kex_algo = state.ciphersuite().kexAlgo();
        
        if (kex_algo == "RSA")
        {
            assert(state.serverCerts() && !state.serverCerts().certChain().empty,
                         "RSA key exchange negotiated so server sent a certificate");
            
            if (!server_rsa_kex_key)
                throw new InternalError("Expected RSA kex but no server kex key set");
            
            if (!cast(const RSAPrivateKey)(server_rsa_kex_key))
                throw new InternalError("Expected RSA key but got " ~ server_rsa_kex_key.algo_name);
            
            auto decryptor = scoped!PKDecryptorEME(*server_rsa_kex_key, "PKCS1v15");
            
            TLSProtocolVersion client_version = state.clientHello().Version();
            
            /*
            * This is used as the pre-master if RSA decryption fails.
            * Otherwise we can be used as an oracle. See Bleichenbacher
            * "Chosen Ciphertext Attacks against Protocols Based on RSA
            * Encryption Standard PKCS #1", Crypto 98
            *
            * Create it here instead if in the catch clause as otherwise we
            * expose a timing channel WRT the generation of the fake value.
            * Some timing channel likely remains due to exception handling
            * and the like.
            */
            SecureVector!ubyte fake_pre_master = rng.randomVec(48);
            fake_pre_master[0] = client_version.majorVersion();
            fake_pre_master[1] = client_version.minorVersion();
            
            try
            {
                if (state.Version() == TLSProtocolVersion.SSL_V3)
                {
                    m_pre_master = decryptor.decrypt(contents);
                }
                else
                {
                    TLSDataReader reader = TLSDataReader("ClientKeyExchange", contents);
                    m_pre_master = decryptor.decrypt(reader.getRange!ubyte(2, 0, 65535));
                }
                
                if (m_pre_master.length != 48 ||
                    client_version.majorVersion() != m_pre_master[0] ||
                    client_version.minorVersion() != m_pre_master[1])
                {
                    throw new DecodingError("ClientKeyExchange: Secret corrupted");
                }
            }
            catch (Throwable)
            {
                m_pre_master = fake_pre_master;
            }
        }
        else
        {
            TLSDataReader reader = TLSDataReader("ClientKeyExchange", contents);
            
            SymmetricKey psk;
            
            if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
            {
                const string psk_identity = reader.getString(2, 0, 65535);
                
                psk = creds.psk("tls-server",
                                state.clientHello().sniHostname(),
                                psk_identity);
                
                if (psk.length == 0)
                {
                    if (policy.hideUnknownUsers())
                        psk = SymmetricKey(rng, 16);
                    else
                        throw new TLSException(TLSAlert.UNKNOWN_PSK_IDENTITY,
                                                "No PSK for identifier " ~ psk_identity);
                }
            }
            
            if (kex_algo == "PSK")
            {
                Vector!ubyte zeros = Vector!ubyte(psk.length);
                appendTlsLengthValue(m_pre_master, zeros, 2);
                appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
            }
            else if (kex_algo == "SRP_SHA")
            {
                SRP6ServerSession srp = state.serverKex().serverSrpParams();
                
                m_pre_master = srp.step2(BigInt.decode(reader.getRange!ubyte(2, 0, 65535))).bitsOf();
            }
            else if (kex_algo == "DH" || kex_algo == "DHE_PSK" ||
                     kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
            {
                const PrivateKey private_key = state.serverKex().serverKexKey();
                
                const PKKeyAgreementKey ka_key = cast(const PKKeyAgreementKey)(private_key);
                
                if (!ka_key)
                    throw new InternalError("Expected key agreement key type but got " ~
                                             private_key.algo_name);
                
                try
                {
                    auto ka = scoped!PKKeyAgreement(ka_key, "Raw");
                    
                    Vector!ubyte client_pubkey;
                    
                    if (ka_key.algo_name == "DH")
                        client_pubkey = reader.getRange!ubyte(2, 0, 65535);
                    else
                        client_pubkey = reader.getRange!ubyte(1, 0, 255);
                    
                    SecureVector!ubyte shared_secret = ka.deriveKey(0, client_pubkey).bitsOf();
                    
                    if (ka_key.algo_name == "DH")
                        shared_secret = stripLeadingZeros(shared_secret);
                    
                    if (kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
                    {
                        appendTlsLengthValue(m_pre_master, shared_secret, 2);
                        appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
                    }
                    else
                        m_pre_master = shared_secret;
                }
                catch(Exception e)
                {
                    /*
                    * Something failed in the DH computation. To avoid possible
                    * timing attacks, randomize the pre-master output and carry
                    * on, allowing the protocol to fail later in the finished
                    * checks.
                    */
                    m_pre_master = rng.randomVec(ka_key.publicValue().length);
                }
            }
            else
                throw new InternalError("ClientKeyExchange: Unknown kex type " ~ kex_algo);
        }
    }

    /*
    * Create a new TLSClient Key Exchange message
    */
    this(HandshakeIO io,
         HandshakeState state,
         in TLSPolicy policy,
         TLSCredentialsManager creds,
         const PublicKey server_public_key,
         in string hostname,
         RandomNumberGenerator rng)
    {
        const string kex_algo = state.ciphersuite().kexAlgo();
        
        if (kex_algo == "PSK")
        {
            string identity_hint = "";
            
            if (state.serverKex())
            {
                TLSDataReader reader = TLSDataReader("ClientKeyExchange", state.serverKex().params());
                identity_hint = reader.getString(2, 0, 65535);
            }
            
            const string hostname = state.clientHello().sniHostname();
            
            const string psk_identity = creds.pskIdentity("tls-client",
                                                           hostname,
                                                           identity_hint);
            
            appendTlsLengthValue(m_key_material, psk_identity, 2);
            
            SymmetricKey psk = creds.psk("tls-client", hostname, psk_identity);
            
            Vector!ubyte zeros = Vector!ubyte(psk.length);
            
            appendTlsLengthValue(m_pre_master, zeros, 2);
            appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
        }
        else if (state.serverKex())
        {
            TLSDataReader reader = TLSDataReader("ClientKeyExchange", state.serverKex().params());
            
            SymmetricKey psk;
            
            if (kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
            {
                string identity_hint = reader.getString(2, 0, 65535);
                
                const string hostname = state.clientHello().sniHostname();
                
                const string psk_identity = creds.pskIdentity("tls-client",
                                                               hostname,
                                                               identity_hint);
                
                appendTlsLengthValue(m_key_material, psk_identity, 2);
                
                psk = creds.psk("tls-client", hostname, psk_identity);
            }
            
            if (kex_algo == "DH" || kex_algo == "DHE_PSK")
            {
                BigInt p = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                BigInt g = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                BigInt Y = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                
                if (reader.remainingBytes())
                    throw new DecodingError("Bad params size for DH key exchange");
                
                if (p.bits() < policy.minimumDhGroupSize())
                    throw new TLSException(TLSAlert.INSUFFICIENT_SECURITY,
                                            "TLSServer sent DH group of " ~
                                            to!string(p.bits()) ~
                                            " bits, policy requires at least " ~
                                            to!string(policy.minimumDhGroupSize()));
                
                /*
                * A basic check for key validity. As we do not know q here we
                * cannot check that Y is in the right subgroup. However since
                * our key is ephemeral there does not seem to be any
                * advantage to bogus keys anyway.
                */
                if (Y <= 1 || Y >= p - 1)
                    throw new TLSException(TLSAlert.INSUFFICIENT_SECURITY,
                                            "TLSServer sent bad DH key for DHE exchange");
                
                DLGroup group = DLGroup(p, g);
                
                if (!group.verifyGroup(rng, true))
                    throw new InternalError("DH group failed validation, possible attack");
                auto counterparty_key = scoped!DHPublicKey(group, Y);
                
                auto priv_key = scoped!DHPrivateKey(rng, group);
                
                auto ka = scoped!PKKeyAgreement(priv_key, "Raw");
                
                SecureVector!ubyte dh_secret = stripLeadingZeros(
                    ka.deriveKey(0, counterparty_key.publicValue()).bitsOf());
                
                if (kex_algo == "DH")
                    m_pre_master = dh_secret;
                else
                {
                    appendTlsLengthValue(m_pre_master, dh_secret, 2);
                    appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
                }
                
                appendTlsLengthValue(m_key_material, priv_key.publicValue(), 2);
            }
            else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
            {
                const ubyte curve_type = reader.get_byte();
                
                if (curve_type != 3)
                    throw new DecodingError("TLSServer sent non-named ECC curve");
                
                const ushort curve_id = reader.get_ushort();
                
                const string name = SupportedEllipticCurves.curveIdToName(curve_id);
                
                if (name == "")
                    throw new DecodingError("TLSServer sent unknown named curve " ~ to!string(curve_id));
                
                ECGroup group = ECGroup(name);
                
                Vector!ubyte ecdh_key = reader.getRange!ubyte(1, 1, 255);
                
                auto counterparty_key = scoped!ECDHPublicKey(group, OS2ECP(ecdh_key, group.getCurve()));
                
                auto priv_key = scoped!ECDHPrivateKey(rng, group);
                
                auto ka = scoped!PKKeyAgreement(priv_key, "Raw");
                
                SecureVector!ubyte ecdh_secret =
                    ka.deriveKey(0, counterparty_key.publicValue()).bitsOf();
                
                if (kex_algo == "ECDH")
                    m_pre_master = ecdh_secret;
                else
                {
                    appendTlsLengthValue(m_pre_master, ecdh_secret, 2);
                    appendTlsLengthValue(m_pre_master, psk.bitsOf(), 2);
                }
                
                appendTlsLengthValue(m_key_material, priv_key.publicValue(), 1);
            }
            else if (kex_algo == "SRP_SHA")
            {
                const BigInt N = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                const BigInt g = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                Vector!ubyte salt = reader.getRange!ubyte(1, 1, 255);
                const BigInt B = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                
                const string srp_group = srp6GroupIdentifier(N, g);
                
                const string srp_identifier = creds.srpIdentifier("tls-client", hostname);
                
                const string srp_password = creds.srpPassword("tls-client", hostname, srp_identifier);
                
                Pair!(BigInt, SymmetricKey) srp_vals = srp6ClientAgree(srp_identifier,
                                                                       srp_password,
                                                                       srp_group,
                                                                       "SHA-1",
                                                                       salt,
                                                                       B,
                                                                       rng);
                
                appendTlsLengthValue(m_key_material, BigInt.encode(srp_vals.first), 2);
                m_pre_master = srp_vals.second.bitsOf();
            }
            else
            {
                throw new InternalError("ClientKeyExchange: Unknown kex " ~
                                         kex_algo);
            }
            
            reader.assertDone();
        }
        else
        {
            // No server key exchange msg better mean RSA kex + RSA key in cert
            
            if (kex_algo != "RSA")
                throw new TLSUnexpectedMessage("No server kex but negotiated kex " ~ kex_algo);
            
            if (!server_public_key)
                throw new InternalError("No server public key for RSA exchange");
            
            if (auto rsa_pub = cast(const RSAPublicKey)(server_public_key))
            {
                const TLSProtocolVersion offered_version = state.clientHello().Version();
                
                m_pre_master = rng.randomVec(48);
                m_pre_master[0] = offered_version.majorVersion();
                m_pre_master[1] = offered_version.minorVersion();
                
                auto encryptor = scoped!PKEncryptorEME(rsa_pub, "PKCS1v15");
                
                Vector!ubyte encrypted_key = encryptor.encrypt(m_pre_master, rng);
                
                if (state.Version() == TLSProtocolVersion.SSL_V3)
                    m_key_material = encrypted_key; // no length field
                else
                    appendTlsLengthValue(m_key_material, encrypted_key, 2);
            }
            else
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE,
                                        "Expected a RSA key in server cert but got " ~
                                        server_public_key.algo_name);
        }
        
        state.hash().update(io.send(this));
    }


private:
    override Vector!ubyte serialize() const { return m_key_material; }

    Vector!ubyte m_key_material;
    SecureVector!ubyte m_pre_master;
}

/**
* Certificate Message
*/
final class Certificate : HandshakeMessage
{
public:
    override HandshakeType type() const { return CERTIFICATE; }
    Vector!X509Certificate certChain() const { return m_certs; }

    size_t count() const { return m_certs.length; }
    @property bool empty() const { return m_certs.empty; }

    /**
    * Create a new Certificate message
    */
    this(HandshakeIO io,
         HandshakeHash hash,
         in Vector!X509Certificate cert_list)
    {
        m_certs = cert_list;
        hash.update(io.send(this));
    }

    /**
    * Deserialize a Certificate message
    */
    this(in Vector!ubyte buf)
    {
        if (buf.length < 3)
            throw new DecodingError("Certificate: Message malformed");
        
        const size_t total_size = make_uint(0, buf[0], buf[1], buf[2]);

        if (total_size != buf.length - 3)
            throw new DecodingError("Certificate: Message malformed");
        
        const ubyte* certs = &buf[3];
        
        while (true)
        {
            size_t remaining_bytes = &buf[buf.length] - certs;
            if (remaining_bytes <= 0)
                break;
            if (remaining_bytes < 3)
                throw new DecodingError("Certificate: Message malformed");
            
            const size_t cert_size = make_uint(0, certs[0], certs[1], certs[2]);
            
            if (remaining_bytes < (3 + cert_size))
                throw new DecodingError("Certificate: Message malformed");
            
            auto cert_buf = scoped!DataSourceMemory(&certs[3], cert_size);
            m_certs.pushBack(X509Certificate(cert_buf));
            
            certs += cert_size + 3;
        }
    }

private:
    /**
    * Serialize a Certificate message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf = Vector!ubyte(3);
        
        for (size_t i = 0; i != m_certs.length; ++i)
        {
            Vector!ubyte raw_cert = m_certs[i].BER_encode();
            const size_t cert_size = raw_cert.length;
            foreach (size_t i; 0 .. 3)
                buf.pushBack(get_byte!uint(i+1, cert_size));
            buf += raw_cert;
        }
        
        const size_t buf_size = buf.length - 3;
        foreach (size_t i; 0 .. 3)
            buf[i] = get_byte!uint(i+1, buf_size);
        
        return buf;
    }

    Vector!X509Certificate m_certs;
}

/**
* Certificate Request Message
*/
final class CertificateReq : HandshakeMessage
{
public:
    override HandshakeType type() const { return CERTIFICATE_REQUEST; }

    Vector!string acceptableCertTypes() const
    { return m_cert_key_types; }

    Vector!X509DN acceptableCAs() const { return m_names; }

    Vector!( Pair!(string, string)  ) supportedAlgos() const
    { return m_supported_algos; }

    /**
    * Create a new Certificate Request message
    */
    this(HandshakeIO io,
         HandshakeHash hash,
         in TLSPolicy policy,
         in Vector!X509DN ca_certs,
         TLSProtocolVersion _version) 
    {
        m_names = ca_certs;
        m_cert_key_types = [ "RSA", "DSA", "ECDSA" ];
        if (_version.supportsNegotiableSignatureAlgorithms())
        {
            Vector!string hashes = policy.allowedSignatureHashes();
            Vector!string sigs = policy.allowedSignatureMethods();
            
            for (size_t i = 0; i != hashes.length; ++i)
                for (size_t j = 0; j != sigs.length; ++j)
                    m_supported_algos.pushBack(Pair(hashes[i], sigs[j]));
        }
        
        hash.update(io.send(this));
    }

    /**
    * Deserialize a Certificate Request message
    */
    this(in Vector!ubyte buf, TLSProtocolVersion _version)
    {
        if (buf.length < 4)
            throw new DecodingError("Certificate_Req: Bad certificate request");
        
        TLSDataReader reader = TLSDataReader("CertificateRequest", buf);

        Vector!ubyte cert_type_codes = reader.getRangeVector!ubyte(1, 1, 255);
        
        for (size_t i = 0; i != cert_type_codes.length; ++i)
        {
            const string cert_type_name = certTypeCodeToName(cert_type_codes[i]);
            
            if (cert_type_name == "") // something we don't know
                continue;
            
            m_cert_key_types.pushBack(cert_type_name);
        }
        
        if (_version.supportsNegotiableSignatureAlgorithms())
        {
            Vector!ubyte sig_hash_algs = reader.getRangeVector!ubyte(2, 2, 65534);
            
            if (sig_hash_algs.length % 2 != 0)
                throw new DecodingError("Bad length for signature IDs in certificate request");
            
            for (size_t i = 0; i != sig_hash_algs.length; i += 2)
            {
                string hash = SignatureAlgorithms.hashAlgoName(sig_hash_algs[i]);
                string sig = SignatureAlgorithms.sigAlgoName(sig_hash_algs[i+1]);
                m_supported_algos.pushBack(Pair(hash, sig));
            }
        }
        
        const ushort purported_size = reader.get_ushort();
        
        if (reader.remainingBytes() != purported_size)
            throw new DecodingError("Inconsistent length in certificate request");
        
        while (reader.hasRemaining())
        {
            Vector!ubyte name_bits = reader.getRangeVector!ubyte(2, 0, 65535);
            
            BERDecoder decoder = BERDecoder(name_bits.ptr, name_bits.length);
            X509DN name;
            decoder.decode(name);
            m_names.pushBack(name);
        }
    }

private:

    /**
    * Serialize a Certificate Request message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        
        Vector!ubyte cert_types;
        
        for (size_t i = 0; i != m_cert_key_types.length; ++i)
            cert_types.pushBack(certTypeNameToCode(m_cert_key_types[i]));
        
        appendTlsLengthValue(buf, cert_types, 1);
        
        if (!m_supported_algos.empty)
            buf += SignatureAlgorithms(m_supported_algos).serialize();
        
        Vector!ubyte encoded_names;
        
        for (size_t i = 0; i != m_names.length; ++i)
        {
            DEREncoder encoder = DEREncoder();
            encoder.encode(m_names[i]);
            
            appendTlsLengthValue(encoded_names, encoder.getContents(), 2);
        }
        
        appendTlsLengthValue(buf, encoded_names, 2);
        
        return buf;
    }

    Vector!X509DN m_names;
    Vector!string m_cert_key_types;

    Vector!( Pair!(string, string)  ) m_supported_algos;
}

/**
* Certificate Verify Message
*/
final class CertificateVerify : HandshakeMessage
{
public:
    override HandshakeType type() const { return CERTIFICATE_VERIFY; }

    /**
    * Check the signature on a certificate verify message
    * @param cert = the purported certificate
    * @param state = the handshake state
    */
    bool verify(const X509Certificate cert,
                const HandshakeState state) const
    {
        Unique!PublicKey key = cert.subjectPublicKey();
        
        Pair!(string, Signature_Format) format = state.understandSigFormat(*key, m_hash_algo, m_sig_algo, true);
        
        PKVerifier verifier = PKVerifier(*key, format.first, format.second);
        if (state.Version() == TLSProtocolVersion.SSL_V3)
        {
            SecureVector!ubyte md5_sha = state.hash().finalSSL3(state.sessionKeys().masterSecret());

            return verifier.verifyMessage(&md5_sha[16], md5_sha.length-16,
            m_signature.ptr, m_signature.length);
        }
        
        return verifier.verifyMessage(state.hash().getContents(), m_signature);
    }

    /*
    * Create a new Certificate Verify message
    */
    this(HandshakeIO io,
         HandshakeState state,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         const PrivateKey priv_key)
    {
        assert(priv_key, "No private key defined");
        
        Pair!(string, Signature_Format) format = state.chooseSigFormat(priv_key, m_hash_algo, m_sig_algo, true, policy);
        
        PKSigner signer = PKSigner(priv_key, format.first, format.second);
        
        if (state.Version() == TLSProtocolVersion.SSL_V3)
        {
            SecureVector!ubyte md5_sha = state.hash().finalSSL3(state.sessionKeys().masterSecret());
            
            if (priv_key.algo_name == "DSA")
                m_signature = signer.signMessage(&md5_sha[16], md5_sha.length-16, rng);
            else
                m_signature = signer.signMessage(md5_sha, rng);
        }
        else
        {
            m_signature = signer.signMessage(state.hash().getContents(), rng);
        }
        
        state.hash().update(io.send(this));
    }

    /*
    * Deserialize a Certificate Verify message
    */
    this(in Vector!ubyte buf,
         TLSProtocolVersion _version)
    {
        TLSDataReader reader = TLSDataReader("CertificateVerify", buf);
        
        if (_version.supportsNegotiableSignatureAlgorithms())
        {
            m_hash_algo = SignatureAlgorithms.hashAlgoName(reader.get_byte());
            m_sig_algo = SignatureAlgorithms.sigAlgoName(reader.get_byte());
        }
        
        m_signature = reader.getRange!ubyte(2, 0, 65535);
    }
private:
    /*
    * Serialize a Certificate Verify message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        
        if (m_hash_algo != "" && m_sig_algo != "")
        {
            buf.pushBack(SignatureAlgorithms.hashAlgoCode(m_hash_algo));
            buf.pushBack(SignatureAlgorithms.sigAlgoCode(m_sig_algo));
        }
        
        const ushort sig_len = m_signature.length;
        buf.pushBack(get_byte(0, sig_len));
        buf.pushBack(get_byte(1, sig_len));
        buf += m_signature;
        
        return buf;
    }

    string m_sig_algo; // sig algo used to create signature
    string m_hash_algo; // hash used to create signature
    Vector!ubyte m_signature;
}

/**
* Finished Message
*/
final class Finished : HandshakeMessage
{
public:
    override HandshakeType type() const { return FINISHED; }

    Vector!ubyte verifyData() const
    { return m_verification_data; }

    /*
    * Verify a Finished message
    */
    bool verify(in HandshakeState state, ConnectionSide side) const
    {
        return (m_verification_data == finishedComputeVerify(state, side));
    }

    /*
    * Create a new Finished message
    */
    this(HandshakeIO io,
         HandshakeState state,
         ConnectionSide side)
    {
        m_verification_data = finishedComputeVerify(state, side);
        state.hash().update(io.send(this));
    }

    /*
    * Deserialize a Finished message
    */
    this(in Vector!ubyte buf)
    {
        m_verification_data = buf;
    }
private:
    /*
    * Serialize a Finished message
    */
    override Vector!ubyte serialize() const
    {
        return m_verification_data;
    }

    Vector!ubyte m_verification_data;
}

/**
* Hello Request Message
*/
final class HelloRequest : HandshakeMessage
{
public:
    override HandshakeType type() const { return HELLO_REQUEST; }

    /*
    * Create a new Hello Request message
    */
    this(HandshakeIO io)
    {
        io.send(this);
    }

    /*
    * Deserialize a Hello Request message
    */
    this(in Vector!ubyte buf)
    {
        if (buf.length)
            throw new DecodingError("Bad HelloRequest, has non-zero size");
    }
private:
    /*
    * Serialize a Hello Request message
    */
    Vector!ubyte serialize() const
    {
        return Vector!ubyte();
    }
}

/**
* TLSServer Key Exchange Message
*/
final class ServerKeyExchange : HandshakeMessage
{
public:
    override HandshakeType type() const { return SERVER_KEX; }

    Vector!ubyte params() const { return m_params; }

    /**
    * Verify a TLSServer Key Exchange message
    */
    bool verify(in PublicKey server_key,
                const HandshakeState state) const
    {
        Pair!(string, Signature_Format) format = state.understandSigFormat(server_key, m_hash_algo, m_sig_algo, false);
        
        PKVerifier verifier = PKVerifier(server_key, format.first, format.second);
        verifier.update(state.clientHello().random());
        verifier.update(state.serverHello().random());
        verifier.update(params());
        
        return verifier.checkSignature(m_signature);
    }

    // Only valid for certain kex types
    PrivateKey serverKexKey() const
    {
        assert(m_kex_key, "PrivateKey cannot be null");
        return *m_kex_key;
    }

    // Only valid for SRP negotiation
    SRP6ServerSession serverSrpParams() const
    {
        assert(m_srp_params, "SRP6ServerSession cannot be null");
        return *m_srp_params;
    }

    /**
    * Deserialize a TLSServer Key Exchange message
    */
    this(in Vector!ubyte buf,
         in string kex_algo,
         in string sig_algo,
         TLSProtocolVersion _version) 
    {
        m_kex_key.clear();
        m_srp_params.clear();
        if (buf.length < 6)
            throw new DecodingError("ServerKeyExchange: Packet corrupted");
        
        TLSDataReader reader = TLSDataReader("ServerKeyExchange", buf);
        
        /*
        * We really are just serializing things back to what they were
        * before, but unfortunately to know where the signature is we need
        * to be able to parse the whole thing anyway.
        */
        
        if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
        {
            const string identity_hint = reader.getString(2, 0, 65535);
            appendTlsLengthValue(m_params, identity_hint, 2);
        }
        
        if (kex_algo == "DH" || kex_algo == "DHE_PSK")
        {
            // 3 bigints, DH p, g, Y
            
            foreach (size_t i; 0 .. 3)
            {
                BigInt v = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
                appendTlsLengthValue(m_params, BigInt.encode(v), 2);
            }
        }
        else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
        {
            const ubyte curve_type = reader.get_byte();
            
            if (curve_type != 3)
                throw new DecodingError("ServerKeyExchange: TLSServer sent non-named ECC curve");
            
            const ushort curve_id = reader.get_ushort();
            
            const string name = SupportedEllipticCurves.curveIdToName(curve_id);
            
            Vector!ubyte ecdh_key = reader.getRange!ubyte(1, 1, 255);
            
            if (name == "")
                throw new DecodingError("ServerKeyExchange: TLSServer sent unknown named curve " ~
                                         to!string(curve_id));
            
            m_params.pushBack(curve_type);
            m_params.pushBack(get_byte(0, curve_id));
            m_params.pushBack(get_byte(1, curve_id));
            appendTlsLengthValue(m_params, ecdh_key, 1);
        }
        else if (kex_algo == "SRP_SHA")
        {
            // 2 bigints (N,g) then salt, then server B
            
            const BigInt N = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
            const BigInt g = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
            Vector!ubyte salt = reader.getRange!ubyte(1, 1, 255);
            const BigInt B = BigInt.decode(reader.getRange!ubyte(2, 1, 65535));
            
            appendTlsLengthValue(m_params, BigInt.encode(N), 2);
            appendTlsLengthValue(m_params, BigInt.encode(g), 2);
            appendTlsLengthValue(m_params, salt, 1);
            appendTlsLengthValue(m_params, BigInt.encode(B), 2);
        }
        else if (kex_algo != "PSK")
                throw new DecodingError("ServerKeyExchange: Unsupported kex type " ~ kex_algo);
        
        if (sig_algo != "")
        {
            if (_version.supportsNegotiableSignatureAlgorithms())
            {
                m_hash_algo = SignatureAlgorithms.hashAlgoName(reader.get_byte());
                m_sig_algo = SignatureAlgorithms.sigAlgoName(reader.get_byte());
            }
            
            m_signature = reader.getRange!ubyte(2, 0, 65535);
        }
        
        reader.assertDone();
    }

    /**
    * Create a new TLSServer Key Exchange message
    */
    this(HandshakeIO io,
         HandshakeState state,
         in TLSPolicy policy,
         TLSCredentialsManager creds,
         RandomNumberGenerator rng,
         in PrivateKey signing_key = null)
    {
        const string hostname = state.clientHello().sniHostname();
        const string kex_algo = state.ciphersuite().kexAlgo();
        
        if (kex_algo == "PSK" || kex_algo == "DHE_PSK" || kex_algo == "ECDHE_PSK")
        {
            string identity_hint = creds.pskIdentityHint("tls-server", hostname);
            
            appendTlsLengthValue(m_params, identity_hint, 2);
        }
        
        if (kex_algo == "DH" || kex_algo == "DHE_PSK")
        {
            Unique!DHPrivateKey dh = new DHPrivateKey(rng, policy.dhGroup());

            appendTlsLengthValue(m_params, BigInt.encode(dh.getDomain().getP()), 2);
            appendTlsLengthValue(m_params, BigInt.encode(dh.getDomain().getG()), 2);
            appendTlsLengthValue(m_params, dh.publicValue(), 2);
            m_kex_key = dh.release();
        }
        else if (kex_algo == "ECDH" || kex_algo == "ECDHE_PSK")
        {
            const Vector!string curves = state.clientHello().supportedEccCurves();
            
            if (curves.empty)
                throw new InternalError("TLSClient sent no ECC extension but we negotiated ECDH");
            
            const string curve_name = policy.chooseCurve(curves);
            
            if (curve_name == "")
                throw new TLSException(TLSAlert.HANDSHAKE_FAILURE, "Could not agree on an ECC curve with the client");

            ECGroup ec_group = ECGroup(curve_name);
            
            Unique!ECDHPrivateKey ecdh = new ECDHPrivateKey(rng, ec_group);
            
            const string ecdh_domain_oid = ecdh.domain().getOid();
            const string domain = OIDS.lookup(OID(ecdh_domain_oid));
            
            if (domain == "")
                throw new InternalError("Could not find name of ECDH domain " ~ ecdh_domain_oid);
            
            const ushort named_curve_id = SupportedEllipticCurves.nameToCurveId(domainput);
            
            m_params.pushBack(3); // named curve
            m_params.pushBack(get_byte(0, named_curve_id));
            m_params.pushBack(get_byte(1, named_curve_id));
            
            appendTlsLengthValue(m_params, ecdh.publicValue(), 1);
            
            m_kex_key = ecdh.release();
        }
        else if (kex_algo == "SRP_SHA")
        {
            const string srp_identifier = state.clientHello().srpIdentifier();
            
            string group_id;
            BigInt v;
            Vector!ubyte salt;
            
            const bool found = creds.srpVerifier("tls-server", hostname,
                                                  srp_identifier,
                                                  group_id, v, salt,
                                                  policy.hideUnknownUsers());
            
            if (!found)
                throw new TLSException(TLSAlert.UNKNOWN_PSK_IDENTITY, "Unknown SRP user " ~ srp_identifier);
            
            m_srp_params = new SRP6ServerSession;
            
            BigInt B = m_srp_params.step1(v, group_id, "SHA-1", rng);
            
            DLGroup group = DLGroup(group_id);

            appendTlsLengthValue(m_params, BigInt.encode(group.getP()), 2);
            appendTlsLengthValue(m_params, BigInt.encode(group.getG()), 2);
            appendTlsLengthValue(m_params, salt, 1);
            appendTlsLengthValue(m_params, BigInt.encode(B), 2);
        }
        else if (kex_algo != "PSK")
            throw new InternalError("ServerKeyExchange: Unknown kex type " ~ kex_algo);
        
        if (state.ciphersuite().sigAlgo() != "")
        {
            assert(signing_key, "Signing key was set");
            
            Pair!(string, Signature_Format) format = state.chooseSigFormat(signing_key, m_hash_algo, m_sig_algo, false, policy);
            
            PKSigner signer = PKSigner(signing_key, format.first, format.second);
            
            signer.update(state.clientHello().random());
            signer.update(state.serverHello().random());
            signer.update(params());
            m_signature = signer.signature(rng);
        }
        
        state.hash().update(io.send(this));
    }


    ~this() {}
private:
    /**
    * Serialize a TLSServer Key Exchange message
    */
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf = params();
        
        if (m_signature.length)
        {
            // This should be an explicit version check
            if (m_hash_algo != "" && m_sig_algo != "")
            {
                buf.pushBack(SignatureAlgorithms.hashAlgoCode(m_hash_algo));
                buf.pushBack(SignatureAlgorithms.sigAlgoCode(m_sig_algo));
            }
            
            appendTlsLengthValue(buf, m_signature, 2);
        }
        
        return buf;
    }

    Unique!PrivateKey m_kex_key;
    Unique!SRP6ServerSession m_srp_params;

    Vector!ubyte m_params;

    string m_sig_algo; // sig algo used to create signature
    string m_hash_algo; // hash used to create signature
    Vector!ubyte m_signature;
}

/**
* TLSServer Hello Done Message
*/
final class ServerHelloDone : HandshakeMessage
{
public:
    override HandshakeType type() const { return SERVER_HELLO_DONE; }

    /*
    * Create a new TLSServer Hello Done message
    */
    this(HandshakeIO io, HandshakeHash hash)
    {
        hash.update(io.send(this));
    }

    /*
    * Deserialize a TLSServer Hello Done message
    */
    this(in Vector!ubyte buf)
    {
        if (buf.length)
            throw new DecodingError("ServerHello_Done: Must be empty, and is not");
    }
private:
    /*
    * Serialize a TLSServer Hello Done message
    */
    override Vector!ubyte serialize() const
    {
        return Vector!ubyte();
    }
}

/**
* Next Protocol Message
*/
final class NextProtocol : HandshakeMessage
{
public:
    override HandshakeType type() const { return NEXT_PROTOCOL; }

    string protocol() const { return m_protocol; }

    this(in Vector!ubyte buf)
    {
        TLSDataReader reader = TLSDataReader("NextProtocol", buf);
        
        m_protocol = reader.getString(1, 0, 255);
        
        reader.getRangeVector!ubyte(1, 0, 255); // padding, ignored
    }

    this(HandshakeIO io,
         HandshakeHash hash,
         in string protocol)
    {
        hash.update(io.send(this));
        m_protocol = protocol;
    }

private:

    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf;
        
        appendTlsLengthValue(buf,
                                cast(const ubyte*)(m_protocol.ptr),
                                m_protocol.length,
                                1);
        
        const ubyte padding_len = 32 - ((m_protocol.length + 2) % 32);
        
        buf.pushBack(padding_len);
        
        foreach (size_t i; 0 .. padding_len)
            buf.pushBack(0);
        
        return buf;
    }

    string m_protocol;
}

/**
* New TLSSession Ticket Message
*/
final class NewSessionTicket : HandshakeMessage
{
public:
    override HandshakeType type() const { return NEW_SESSION_TICKET; }

    uint ticketLifetimeHint() const { return m_ticket_lifetime_hint; }
    Vector!ubyte ticket() const { return m_ticket; }

    this(HandshakeIO io,
         HandshakeHash hash,
         in Vector!ubyte ticket,
         Duration lifetime) 
        
    {    m_ticket_lifetime_hint = lifetime;
        m_ticket = ticket;
        hash.update = io.send(this);
    }

    this(in Vector!ubyte buf)
    {
        if (buf.length < 6)
            throw new DecodingError("TLSSession ticket message too short to be valid");
        
        TLSDataReader reader = TLSDataReader("SessionTicket", buf);
        
        m_ticket_lifetime_hint = reader.get_uint();
        m_ticket = reader.getRange!ubyte(2, 0, 65535);
    }

    this(HandshakeIO io, HandshakeHash hash)
    {
        hash.update(io.send(this));
    }

private:
    override Vector!ubyte serialize() const
    {
        Vector!ubyte buf = Vector!ubyte(4);
        storeBigEndian(m_ticket_lifetime_hint.seconds, buf.ptr);
        appendTlsLengthValue(buf, m_ticket, 2);
        return buf;
    }

    Duration m_ticket_lifetime_hint;
    Vector!ubyte m_ticket;
}

/**
* Change Cipher Spec
*/
final class ChangeCipherSpec : HandshakeMessage
{
public:
    override HandshakeType type() const { return HANDSHAKE_CCS; }

    override Vector!ubyte serialize() const
    { return Vector!ubyte(1, 1); }
}


private:

string certTypeCodeToName(ubyte code)
{
    switch(code)
    {
        case 1:
            return "RSA";
        case 2:
            return "DSA";
        case 64:
            return "ECDSA";
        default:
            return ""; // DH or something else
    }
}

ubyte certTypeNameToCode(in string name)
{
    if (name == "RSA")
        return 1;
    if (name == "DSA")
        return 2;
    if (name == "ECDSA")
        return 64;
    
    throw new InvalidArgument("Unknown cert type " ~ name);
}


SecureVector!ubyte stripLeadingZeros(in SecureVector!ubyte input)
{
    size_t leading_zeros = 0;
    
    for (size_t i = 0; i != input.length; ++i)
    {
        if (input[i] != 0)
            break;
        ++leading_zeros;
    }
    
    SecureVector!ubyte output = SecureVector!ubyte(input.ptr[leading_zeros .. input.length]);
    return output;
}


/*
* Compute the verifyData
*/
Vector!ubyte finishedComputeVerify(in HandshakeState state,
                                     ConnectionSide side)
{
    if (state.Version() == TLSProtocolVersion.SSL_V3)
    {
        __gshared immutable const(ubyte)[] SSL_CLIENT_LABEL = [ 0x43, 0x4C, 0x4E, 0x54 ];
        __gshared immutable const(ubyte)[] SSL_SERVER_LABEL = [ 0x53, 0x52, 0x56, 0x52 ];
        
        Handshake_Hash hash = state.hash(); // don't modify state
        
        Vector!ubyte ssl3_finished;
        
        if (side == CLIENT)
            hash.update(SSL_CLIENT_LABEL, SSL_CLIENT_LABEL.length);
        else
            hash.update(SSL_SERVER_LABEL, SSL_SERVER_LABEL.length);
        
        return unlock(hash.finalSSL3(state.sessionKeys().masterSecret()));
    }
    else
    {
        __gshared immutable const(ubyte)[] TLS_CLIENT_LABEL = [
            0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74, 0x20, 0x66, 0x69, 0x6E, 0x69,
            0x73, 0x68, 0x65, 0x64 ];
        
        __gshared immutable const(ubyte)[] TLS_SERVER_LABEL = [
            0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x66, 0x69, 0x6E, 0x69,
            0x73, 0x68, 0x65, 0x64 ];
        
        Unique!KDF prf = state.protocolSpecificPrf();
        
        Vector!ubyte input;
        if (side == CLIENT)
            input ~= TLS_CLIENT_LABEL;
        else
            input ~= TLS_SERVER_LABEL;
        
        input ~= state.hash().flushInto(state.Version(), state.ciphersuite().prfAlgo());
        
        return unlock(prf.deriveKey(12, state.sessionKeys().masterSecret(), input));
    }
}

Vector!ubyte makeHelloRandom(RandomNumberGenerator rng)
{
    Vector!ubyte buf = Vector!ubyte(32);
    
    const uint time32 = cast(uint)(Clock.currTime().toUnixTime);
    
    storeBigEndian(time32, buf.ptr);
    rng.randomize(&buf[4], buf.length - 4);
    return buf;
}