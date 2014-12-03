/*
* TLS Server Information
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.server_info;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.utils.types;

/**
* Represents information known about a TLS server.
*/
struct TLSServerInformation
{
public:
    /**
    * @param hostname = the host's DNS name, if known
    * @param port = specifies the protocol port of the server (eg for
    *          TCP/UDP). Zero represents unknown.
    */
    this(in string hostname, ushort port = 0)
    {
        m_hostname = hostname; 
        m_port = port; 
    }

    /**
    * @param hostname = the host's DNS name, if known
    * @param service = is a text string of the service type
    *          (eg "https", "tor", or "git")
    * @param port = specifies the protocol port of the server (eg for
    *          TCP/UDP). Zero represents unknown.
    */
    this(in string hostname,
            in string service,
            ushort port = 0)
    {
        m_hostname = hostname;
        m_service = service;
        m_port = port;
    }

    string hostname() const { return m_hostname; }

    string service() const { return m_service; }

    ushort port() const { return m_port; }

    @property bool empty() const { return m_hostname.empty; }

    bool opEquals(in TLSServerInformation b)
    {
        return (hostname() == b.hostname()) &&
                (service() == b.service()) &&
                (port() == b.port());
        
    }

    bool opCmp(string op)(in TLSServerInformation b)
    {
        return !(this == b);
    }

    bool opCmp(string op)(in TLSServerInformation b)
        if (op == "<")
    {
        if (a.hostname() != b.hostname())
            return (a.hostname() < b.hostname());
        if (a.service() != b.service())
            return (a.service() < b.service());
        if (a.port() != b.port())
            return (a.port() < b.port());
        return false; // equal
    }

private:
    string m_hostname, m_service;
    ushort m_port;
}