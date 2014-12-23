/*
* Hooks for application level policies on TLS connections
* (C) 2004-2006,2013 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.policy;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.tls.version_;
import botan.tls.ciphersuite;
import botan.cert.x509.x509cert;
import botan.pubkey.algo.dl_group;
import botan.tls.ciphersuite;
import botan.tls.magic;
import botan.tls.exceptn;
import botan.utils.containers.multimap;
import std.datetime;
import std.algorithm : uniq, sort;
import std.array : array, Appender;
import std.conv : to;
import botan.utils.types;

/**
* TLS TLSPolicy Base Class
* Inherit and overload as desired to suit local policy concerns
*/
class TLSPolicy
{
public:

    /**
    * Returns a list of ciphers we are willing to negotiate, in
    * order of preference.
    */
    Vector!string allowedCiphers() const
    {
        return Vector!string([
            "AES-256/GCM",
            "AES-128/GCM",
            "AES-256/CCM",
            "AES-128/CCM",
            "AES-256/CCM-8",
            "AES-128/CCM-8",
            //"Camellia-256/GCM",
            //"Camellia-128/GCM",
            "AES-256",
            "AES-128",
            //"Camellia-256",
            //"Camellia-128",
            //"SEED"
            //"3DES",
            //"RC4",
        ]);
    }

    /**
    * Returns a list of hash algorithms we are willing to use for
    * signatures, in order of preference.
    */
    Vector!string allowedSignatureHashes() const
    {
        return Vector!string([
            "SHA-512",
            "SHA-384",
            "SHA-256",
            "SHA-224",
            //"SHA-1",
            //"MD5",
        ]);
    }


    /**
    * Returns a list of MAC algorithms we are willing to use.
    */
    Vector!string allowedMacs() const
    {
        return Vector!string([
            "AEAD",
            "SHA-384",
            "SHA-256",
            "SHA-1",
            //"MD5",
        ]);
    }

    /**
    * Returns a list of key exchange algorithms we are willing to
    * use, in order of preference. Allowed values: DH, empty string
    * (representing RSA using server certificate key)
    */
    Vector!string allowedKeyExchangeMethods() const
    {
        return Vector!string([
            "SRP_SHA",
            //"ECDHE_PSK",
            //"DHE_PSK",
            //"PSK",
            "ECDH",
            "DH",
            "RSA",
        ]);
    }

    /**
    * Returns a list of signature algorithms we are willing to
    * use, in order of preference. Allowed values RSA and DSA.
    */
    Vector!string allowedSignatureMethods() const
    {
        return Vector!string([
            "ECDSA",
            "RSA",
            "DSA",
            //""
        ]);
    }

    /**
    * Return list of ECC curves we are willing to use in order of preference
    */
    Vector!string allowedEccCurves() const
    {
        return Vector!string([
            "brainpool512r1",
            "brainpool384r1",
            "brainpool256r1",
            "secp521r1",
            "secp384r1",
            "secp256r1",
            "secp256k1",
            "secp224r1",
            "secp224k1",
            //"secp192r1",
            //"secp192k1",
            //"secp160r2",
            //"secp160r1",
            //"secp160k1",
        ]);
    }

    /**
    * Returns a list of compression algorithms we are willing to use,
    * in order of preference. Allowed values any value of
    * Compression_Method.
    *
    * @note Compression is not currently supported
    */
    Vector!ubyte compression() const
    {
        return Vector!ubyte([NO_COMPRESSION]);
    }


    /**
    * Choose an elliptic curve to use
    */
    string chooseCurve(in Vector!string curve_names) const
    {
        const Vector!string our_curves = allowedEccCurves();

        for (size_t i = 0; i != our_curves.length; ++i)
            if (valueExists(curve_names, our_curves[i]))
                return our_curves[i];
        
        return ""; // no shared curve
    }

    /**
    * Attempt to negotiate the use of the heartbeat extension
    */
    bool negotiateHeartbeatSupport() const
    {
        return false;
    }

    /**
    * Allow renegotiation even if the counterparty doesn't
    * support the secure renegotiation extension.
    *
    * @warning Changing this to true exposes you to injected
    * plaintext attacks. Read RFC 5746 for background.
    */
    bool allowInsecureRenegotiation() const { return false; }

    /**
    * Allow servers to initiate a new handshake
    */
    bool allowServerInitiatedRenegotiation() const
    {
        return true;
    }

    /**
    * Return the group to use for ephemeral Diffie-Hellman key agreement
    */
    DLGroup dhGroup() const
    {
        return DLGroup("modp/ietf/2048");
    }

    /**
    * Return the minimum DH group size we're willing to use
    */
    size_t minimumDhGroupSize() const
    {
        return 1024;
    }

    /**
    * If this function returns false, unknown SRP/PSK identifiers
    * will be rejected with an unknown_psk_identifier alert as soon
    * as the non-existence is identified. Otherwise, a false
    * identifier value will be used and the protocol allowed to
    * proceed, causing the handshake to eventually fail without
    * revealing that the username does not exist on this system.
    */
    bool hideUnknownUsers() const { return false; }

    /**
    * Return the allowed lifetime of a session ticket. If 0, session
    * tickets do not expire until the session ticket key rolls over.
    * Expired session tickets cannot be used to resume a session.
    */
    Duration sessionTicketLifetime() const
    {
        return 24.hours; // 1 day
    }

    /**
    * @return true if and only if we are willing to accept this version
    * Default accepts only TLS, so if you want to enable DTLS override
    * in your application.
    */
    bool acceptableProtocolVersion(TLSProtocolVersion _version) const
    {
        // By default require TLS to minimize surprise
        if (_version.isDatagramProtocol())
            return false;
        
        return (_version > TLSProtocolVersion.SSL_V3);
    }

    bool acceptableCiphersuite(in TLSCiphersuite) const
    {
        return true;
    }

    /**
    * @return true if servers should choose the ciphersuite matching
    *            their highest preference, rather than the clients.
    *            Has no effect on client side.
    */
    bool serverUsesOwnCiphersuitePreferences() const { return true; }

    /**
    * Return allowed ciphersuites, in order of preference
    */
    Vector!ushort ciphersuiteList(TLSProtocolVersion _version,
                                       bool have_srp) const
    {
        const Vector!string ciphers = allowedCiphers();
        const Vector!string macs = allowedMacs();
        const Vector!string kex = allowedKeyExchangeMethods();
        const Vector!string sigs = allowedSignatureMethods();
        
        CiphersuitePreferenceOrdering order = CiphersuitePreferenceOrdering(ciphers, macs, kex, sigs);
        
        Appender!(TLSCiphersuite[]) ciphersuites;
        
        foreach (const ref TLSCiphersuite suite; TLSCiphersuite.allKnownCiphersuites()[])
        {
            if (!acceptableCiphersuite(suite))
                continue;
            
            if (!have_srp && suite.kexAlgo() == "SRP_SHA")
                continue;
            
            if (_version.isDatagramProtocol() && suite.cipherAlgo() == "RC4")
                continue;
            
            if (!_version.supportsAeadModes() && suite.macAlgo() == "AEAD")
                continue;
            
            if (!valueExists(kex, suite.kexAlgo()))
                continue; // unsupported key exchange
            
            if (!valueExists(ciphers, suite.cipherAlgo()))
                continue; // unsupported cipher
            
            if (!valueExists(macs, suite.macAlgo()))
                continue; // unsupported MAC algo
            
            if (!valueExists(sigs, suite.sigAlgo()))
            {
                // allow if it's an empty sig algo and we want to use PSK
                if (suite.sigAlgo() != "" || !suite.pskCiphersuite())
                    continue;
            }
            
            // OK, allow it:
            ciphersuites ~= suite;
        }
        
        if (ciphersuites.data.length == 0)
            throw new LogicError("TLSPolicy does not allow any available cipher suite");
        Vector!ushort ciphersuite_codes;
        foreach (TLSCiphersuite i; ciphersuites.data.uniq.array.sort!((a,b){ return order.compare(a, b); }).array.to!(TLSCiphersuite[]))
            ciphersuite_codes.pushBack(i.ciphersuiteCode());
        return ciphersuite_codes;
    }

    ~this() {}
}

/**
* NSA Suite B 128-bit security level (see @rfc 6460)
*/
class NSASuiteB128 : TLSPolicy
{
public:
    override Vector!string allowedCiphers() const
    { return Vector!string(["AES-128/GCM"]); }

    override Vector!string allowedSignatureHashes() const
    { return Vector!string(["SHA-256"]); }

    override Vector!string allowedMacs() const
    { return Vector!string(["AEAD"]); }

    override Vector!string allowedKeyExchangeMethods() const
    { return Vector!string(["ECDH"]); }

    override Vector!string allowedSignatureMethods() const
    { return Vector!string(["ECDSA"]); }

    override Vector!string allowedEccCurves() const
    { return Vector!string(["secp256r1"]); }

    override bool acceptableProtocolVersion(TLSProtocolVersion _version) const
    { return _version == TLSProtocolVersion.TLS_V12; }
}

/**
* TLSPolicy for DTLS. We require DTLS v1.2 and an AEAD mode
*/
class DatagramPolicy : TLSPolicy
{
public:
    override Vector!string allowedMacs() const
    { return Vector!string(["AEAD"]); }

    override bool acceptableProtocolVersion(TLSProtocolVersion _version) const
    { return _version == TLSProtocolVersion.DTLS_V12; }
}


private:

struct CiphersuitePreferenceOrdering
{
public:
    this(in Vector!string ciphers, in Vector!string macs, in Vector!string kex, in Vector!string sigs)
    {
        m_ciphers = ciphers;
        m_macs = macs;
        m_kex = kex; 
        m_sigs = sigs;
    }
    
    bool compare(U : TLSCiphersuite)(in TLSCiphersuite a, auto ref U b) const
    {
        if (a.kexAlgo() != b.kexAlgo())
        {
            for (size_t i = 0; i != m_kex.length; ++i)
            {
                if (a.kexAlgo() == m_kex[i])
                    return true;
                if (b.kexAlgo() == m_kex[i])
                    return false;
            }
        }
        
        if (a.cipherAlgo() != b.cipherAlgo())
        {
            for (size_t i = 0; i != m_ciphers.length; ++i)
            {
                if (a.cipherAlgo() == m_ciphers[i])
                    return true;
                if (b.cipherAlgo() == m_ciphers[i])
                    return false;
            }
        }
        
        if (a.cipherKeylen() != b.cipherKeylen())
        {
            if (a.cipherKeylen() < b.cipherKeylen())
                return false;
            if (a.cipherKeylen() > b.cipherKeylen())
                return true;
        }
        
        if (a.sigAlgo() != b.sigAlgo())
        {
            for (size_t i = 0; i != m_sigs.length; ++i)
            {
                if (a.sigAlgo() == m_sigs[i])
                    return true;
                if (b.sigAlgo() == m_sigs[i])
                    return false;
            }
        }
        
        if (a.macAlgo() != b.macAlgo())
        {
            for (size_t i = 0; i != m_macs.length; ++i)
            {
                if (a.macAlgo() == m_macs[i])
                    return true;
                if (b.macAlgo() == m_macs[i])
                    return false;
            }
        }
        
        return false; // equal (?!?)
    }
private:
    const Vector!string m_ciphers, m_macs, m_kex, m_sigs;
}