/*
* TLS TLSSession
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.session;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.cert.x509.x509cert;
import botan.tls.version_;
import botan.tls.ciphersuite;
import botan.tls.magic;
import botan.tls.server_info;
import botan.utils.memory.zeroize;
import botan.algo_base.symkey;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.asn1_str;
import botan.codec.pem;
import botan.rng.rng;
import botan.constructs.cryptobox_psk;
import botan.utils.types;
import core.stdc.time : time_t;
import std.datetime;


/**
* Class representing a TLS session state
*/
struct TLSSession
{
public:
    /**
    * New session (sets session start time)
    */
    this(in Vector!ubyte session_identifier,
         in SecureVector!ubyte master_secret,
         TLSProtocolVersion _version,
         ushort ciphersuite,
         ubyte compression_method,
         ConnectionSide side,
         size_t fragment_size,
         in Vector!X509Certificate certs,
         in Vector!ubyte ticket,
         in TLSServerInformation server_info,
         in string srp_identifier)
    {
        m_start_time = Clock.currTime();
        m_identifier = session_identifier;
        m_session_ticket = ticket;
        m_master_secret = master_secret;
        m_version = _version;
        m_ciphersuite = ciphersuite;
        m_compression_method = compression_method;
        m_connection_side = side;
        m_fragment_size = fragment_size;
        m_peer_certs = certs;
        m_server_info = server_info;
        m_srp_identifier = srp_identifier;
    }

    /**
    * Load a session from DER representation (created by DER_encode)
    */
    this(in ubyte* ber, size_t ber_len)
    {
        ubyte side_code = 0;
        
        ASN1String server_hostname;
        ASN1String server_service;
        size_t server_port;
        
        ASN1String srp_identifier_str;
        
        ubyte major_version = 0, minor_version = 0;
        
        Vector!ubyte peer_cert_bits;
        
        size_t start_time = 0;
        
        BERDecoder(ber, ber_len)
                .startCons(ASN1Tag.SEQUENCE)
                .decodeAndCheck(cast(size_t)(TLS_SESSION_PARAM_STRUCT_VERSION),
                                  "Unknown version in session structure")
                .decodeIntegerType(start_time)
                .decodeIntegerType(major_version)
                .decodeIntegerType(minor_version)
                .decode(m_identifier, ASN1Tag.OCTET_STRING)
                .decode(m_session_ticket, ASN1Tag.OCTET_STRING)
                .decodeIntegerType(m_ciphersuite)
                .decodeIntegerType(m_compression_method)
                .decodeIntegerType(side_code)
                .decodeIntegerType(m_fragment_size)
                .decode(m_master_secret, ASN1Tag.OCTET_STRING)
                .decode(peer_cert_bits, ASN1Tag.OCTET_STRING)
                .decode(server_hostname)
                .decode(server_service)
                .decode(server_port)
                .decode(srp_identifier_str)
                .endCons()
                .verifyEnd();
        
        m_version = TLSProtocolVersion(major_version, minor_version);
        m_start_time = SysTime(unixTimeToStdTime(cast(time_t)start_time));
        m_connection_side = cast(ConnectionSide)(side_code);
        
        m_server_info = TLSServerInformation(server_hostname.value(),
                                           server_service.value(),
                                           server_port);
        
        m_srp_identifier = srp_identifier_str.value();
        
        if (!peer_cert_bits.empty)
        {
            auto certs = scoped!DataSourceMemory(peer_cert_bits.ptr, peer_cert_bits.length);
            while (!certs.endOfData())
                m_peer_certs.pushBack(X509Certificate(certs));
        }
    }

    /**
    * Load a session from PEM representation (created by PEM_encode)
    */
    this(in string pem)
    {
        SecureVector!ubyte der = PEM.decodeCheckLabel(pem, "SSL SESSION");
        
        this(der.ptr, der.length);
    }

    /**
    * Encode this session data for storage
    * @warning if the master secret is compromised so is the
    * session traffic
    */
    SecureVector!ubyte DER_encode() const
    {
        Vector!ubyte peer_cert_bits;
        for (size_t i = 0; i != m_peer_certs.length; ++i)
            peer_cert_bits ~= m_peer_certs[i].BER_encode();
        
        return DEREncoder()
                .startCons(ASN1Tag.SEQUENCE)
                .encode(cast(size_t)(TLS_SESSION_PARAM_STRUCT_VERSION))
                .encode(cast(size_t)(m_start_time.toUnixTime()))
                .encode(cast(size_t)(m_version.majorVersion()))
                .encode(cast(size_t)(m_version.minorVersion()))
                .encode(m_identifier, ASN1Tag.OCTET_STRING)
                .encode(m_session_ticket, ASN1Tag.OCTET_STRING)
                .encode(cast(size_t)(m_ciphersuite))
                .encode(cast(size_t)(m_compression_method))
                .encode(cast(size_t)(m_connection_side))
                .encode(cast(size_t)(m_fragment_size))
                .encode(m_master_secret, ASN1Tag.OCTET_STRING)
                .encode(peer_cert_bits, ASN1Tag.OCTET_STRING)
                .encode(ASN1String(m_server_info.hostname(), ASN1Tag.UTF8_STRING))
                .encode(ASN1String(m_server_info.service(), ASN1Tag.UTF8_STRING))
                .encode(cast(size_t)(m_server_info.port()))
                .encode(ASN1String(m_srp_identifier, ASN1Tag.UTF8_STRING))
                .endCons()
                .getContents();
    }

    /**
    * Encrypt a session (useful for serialization or session tickets)
    */
    Vector!ubyte encrypt(in SymmetricKey master_key, RandomNumberGenerator rng) const
    {
        const auto der = this.DER_encode();
        
        return CryptoBox.encrypt(der.ptr, der.length, master_key, rng);
    }

    /**
    * Decrypt a session created by encrypt
    * @param ctext = the ciphertext returned by encrypt
    * @param ctext_size = the size of ctext in bytes
    * @param key = the same key used by the encrypting side
    */
    static TLSSession decrypt(in ubyte* buf, size_t buf_len, in SymmetricKey master_key)
    {
        try
        {
            const auto ber = CryptoBox.decrypt(buf, buf_len, master_key);
            
            return TLSSession(ber.ptr, ber.length);
        }
        catch(Exception e)
        {
            throw new DecodingError("Failed to decrypt encrypted session -" ~  e.msg);
        }
    }

    /**
    * Decrypt a session created by encrypt
    * @param ctext = the ciphertext returned by encrypt
    * @param key = the same key used by the encrypting side
    */
    static TLSSession decrypt(in Vector!ubyte ctext, in SymmetricKey key)
    {
        return TLSSession.decrypt(ctext.ptr, ctext.length, key);
    }

    /**
    * Encode this session data for storage
    * @warning if the master secret is compromised so is the
    * session traffic
    */
    string PEM_encode() const
    {
        return PEM.encode(this.DER_encode(), "SSL SESSION");
    }

    /**
    * Get the version of the saved session
    */
    TLSProtocolVersion Version() const { return m_version; }

    /**
    * Get the ciphersuite code of the saved session
    */
    ushort ciphersuiteCode() const { return m_ciphersuite; }

    /**
    * Get the ciphersuite info of the saved session
    */
    TLSCiphersuite ciphersuite() const { return TLSCiphersuite.byId(m_ciphersuite); }

    /**
    * Get the compression method used in the saved session
    */
    ubyte compressionMethod() const { return m_compression_method; }

    /**
    * Get which side of the connection the resumed session we are/were
    * acting as.
    */
    ConnectionSide side() const { return m_connection_side; }

    /**
    * Get the SRP identity (if sent by the client in the initial handshake)
    */
    string srpIdentifier() const { return m_srp_identifier; }

    /**
    * Get the saved master secret
    */
    SecureVector!ubyte masterSecret() const { return m_master_secret; }

    /**
    * Get the session identifier
    */
    Vector!ubyte sessionId() const { return m_identifier; }

    /**
    * Get the negotiated maximum fragment size (or 0 if default)
    */
    size_t fragmentSize() const { return m_fragment_size; }

    /**
    * Return the certificate chain of the peer (possibly empty)
    */
    Vector!X509Certificate peerCerts() const { return m_peer_certs; }

    /**
    * Get the wall clock time this session began
    */
    SysTime startTime() const { return m_start_time; }

    /**
    * Return how long this session has existed (in seconds)
    */
    Duration sessionAge() const
    {
        return Clock.currTime() - m_start_time;
    }

    /**
    * Return the session ticket the server gave us
    */
    Vector!ubyte sessionTicket() const { return m_session_ticket; }

    TLSServerInformation serverInfo() const { return m_server_info; }

private:
    enum { TLS_SESSION_PARAM_STRUCT_VERSION = 0x2994e301 }

    SysTime m_start_time;

    Vector!ubyte m_identifier;
    Vector!ubyte m_session_ticket; // only used by client side
    SecureVector!ubyte m_master_secret;

    TLSProtocolVersion m_version;
    ushort m_ciphersuite;
    ubyte m_compression_method;
    ConnectionSide m_connection_side;

    size_t m_fragment_size;

    Vector!X509Certificate m_peer_certs;
    TLSServerInformation m_server_info; // optional
    string m_srp_identifier; // optional
}