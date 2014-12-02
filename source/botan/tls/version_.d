/*
* TLS Protocol Version Management
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.version_;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.get_byte;
import botan.tls.exceptn;
import botan.utils.parsing;
import botan.utils.types;
// import string;

/**
* TLS Protocol Version
*/
struct TLS_Protocol_Version
{
public:
    typedef ushort Version_Code;
    enum : Version_Code {
        SSL_V3                = 0x0300,
        TLS_V10                = 0x0301,
        TLS_V11                = 0x0302,
        TLS_V12                = 0x0303,

        DTLS_V10            = 0xFEFF,
        DTLS_V12            = 0xFEFD
    }

    static TLS_Protocol_Version latest_tls_version()
    {
        return TLS_Protocol_Version(TLS_V12);
    }

    static TLS_Protocol_Version latest_dtls_version()
    {
        return TLS_Protocol_Version(DTLS_V12);
    }

    /**
    * @param named_version = a specific named version of the protocol
    */
    this(Version_Code named_version = 0)
    {
        m_version = cast(ushort) named_version;
    }

    /**
    * @param major = the major version
    * @param minor = the minor version
    */
    this(ubyte major, ubyte minor)
    {
        m_version = (cast(ushort)(major) << 8) | minor; 
    }

    /**
    * @return true if this is a valid protocol version
    */
    bool valid() const { return (m_version != 0); }

    /**
    * @return true if this is a protocol version we know about
    */
    bool known_version() const
    {
        return (m_version == TLS_Protocol_Version.SSL_V3 ||
                m_version == TLS_Protocol_Version.TLS_V10 ||
                m_version == TLS_Protocol_Version.TLS_V11 ||
                m_version == TLS_Protocol_Version.TLS_V12 ||
                m_version == TLS_Protocol_Version.DTLS_V10 ||
                m_version == TLS_Protocol_Version.DTLS_V12);
    }

    /**
    * @return major version of the protocol version
    */
    ubyte major_version() const { return get_byte(0, m_version); }

    /**
    * @return minor version of the protocol version
    */
    ubyte minor_version() const { return get_byte(1, m_version); }

    /**
    * @return human-readable description of this version
    */
    string toString() const
    {
        const ubyte maj = major_version();
        const ubyte min = minor_version();
        
        if (maj == 3 && min == 0)
            return "SSL v3";
        
        if (maj == 3 && min >= 1) // TLS v1.x
            return "TLS v1." ~ to!string(min-1);
        
        if (maj == 254) // DTLS 1.x
            return "DTLS v1." ~ to!string(255 - minput);
        
        // Some very new or very old protocol (or bogus data)
        return "Unknown " ~ to!string(maj) ~ "." ~ to!string(minput);
    }

    /**
    * If this version is known, return that. Otherwise return the
    * best (most recent) version we know of.
    * @return best matching protocol version
    */
    TLS_Protocol_Version best_known_match() const
    {
        if (known_version())
            return this; // known version is its own best match
        
        if (is_datagram_protocol())
            return TLS_Protocol_Version.DTLS_V12;
        else
            return TLS_Protocol_Version.TLS_V12;
    }

    /**
    * @return true iff this is a DTLS version
    */
    bool is_datagram_protocol() const
    {
        return major_version() == 254;
    }

    /**
    * @return true if this version supports negotiable signature algorithms
    */
    bool supports_negotiable_signature_algorithms() const
    {
        return (m_version == TLS_Protocol_Version.TLS_V12 ||
                m_version == TLS_Protocol_Version.DTLS_V12);
    }

    /**
    * @return true if this version uses explicit IVs for block ciphers
    */
    bool supports_explicit_cbc_ivs() const
    {
        return (m_version == TLS_Protocol_Version.TLS_V11 ||
                m_version == TLS_Protocol_Version.TLS_V12 ||
                m_version == TLS_Protocol_Version.DTLS_V10 ||
                m_version == TLS_Protocol_Version.DTLS_V12);
    }

    /**
    * @return true if this version uses a ciphersuite specific PRF
    */
    bool supports_ciphersuite_specific_prf() const
    {
        return (m_version == TLS_Protocol_Version.TLS_V12 ||
                m_version == TLS_Protocol_Version.DTLS_V12);
    }

    bool supports_aead_modes() const
    {
        return (m_version == TLS_Protocol_Version.TLS_V12 ||
                m_version == TLS_Protocol_Version.DTLS_V12);
    }

    /**
    * @return if this version is equal to other
    */
    bool opEquals(in TLS_Protocol_Version other) const
    {
        return (m_version == other.m_version);
    }

    /**
    * @return if this version is not equal to other
    */
    bool opCmp(string op)(in TLS_Protocol_Version other) const
        if (op == "!=")
    {
        return (m_version != other.m_version);
    }

    /**
    * @return if this version is later than other
    */
    bool opCmp(string op)(in TLS_Protocol_Version other) const
        if (op == ">")
    {
        if (this.is_datagram_protocol() != other.is_datagram_protocol())
            throw new TLS_Exception(TLS_Alert.PROTOCOL_VERSION,
                                    "Version comparing " ~ toString() ~ " with " ~ other.toString());
        
        if (this.is_datagram_protocol())
            return m_version < other.m_version; // goes backwards
        
        return m_version > other.m_version;
    }


    /**
    * @return if this version is later than or equal to other
    */
    bool opCmp(string op)(in TLS_Protocol_Version other) const
        if (op == ">=")
    {
        return (this == other || this > other);
    }

private:
    ushort m_version;
}
