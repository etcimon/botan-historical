/*
* TLS Blocking API
* (C) 2013 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.blocking;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.tls.client;
import botan.tls.server;
import botan.rng.rng;
import botan.tls.channel;
import botan.tls.session_manager;
import botan.tls.version_;

alias Secure_Deque(T) = Vector!( T, SecureAllocator);

/**
* Blocking TLS Client
*/
class TLSBlockingClient
{
public:
    this(size_t delegate(ref ubyte[]) read_fn,
         void delegate(in ubyte[]) write_fn,
         TLSSessionManager session_manager,
         TLSCredentialsManager creds,
         in TLSPolicy policy,
         RandomNumberGenerator rng,
         in TLSServerInformation server_info = TLSServerInformation(),
         in TLSProtocolVersion offer_version = TLSProtocolVersion.latestTlsVersion(),
         string delegate(string[]) next_protocol = null)
    {
        m_read_fn = read_fn;
        m_channel = new TLSChannel(write_fn, &data_cb, &alert_cb, &handshake_cb, session_manager, creds,
                                    policy, rng, server_info, offer_version, next_protocol);
    }

    /**
    * Completes full handshake then returns
    */
    final void doHandshake()
    {
        Vector!ubyte readbuf = Vector!ubyte(BOTAN_DEFAULT_BUFFER_SIZE);
        
        while (!m_channel.isClosed() && !m_channel.isActive())
        {
            const size_t from_socket = m_read_fn(readbuf[]);
            m_channel.receivedData(readbuf.ptr, from_socket);
        }
    }

    /**
    * Number of bytes pending read in the plaintext buffer (bytes
    * readable without blocking)
    */
    final size_t pending() const { return m_plaintext.length; }

    /**
    * Blocking read, will return at least 1 ubyte or 0 on connection close
    */
    final size_t read(const(ubyte)* buf, size_t buf_len)
    {
        Vector!ubyte readbuf = Vector!ubyte(BOTAN_DEFAULT_BUFFER_SIZE);
        
        while (m_plaintext.empty && !m_channel.isClosed())
        {
            const size_t from_socket = m_read_fn(readbuf.ptr, readbuf.length);
            m_channel.receivedData(readbuf.ptr, from_socket);
        }
        
        const size_t returned = std.algorithm.min(buf_len, m_plaintext.length);
        
        foreach (size_t i; 0 .. returned)
            buf[i] = m_plaintext[i];
        m_plaintext.erase(m_plaintext.ptr, m_plaintext.ptr + returned);

        assert(returned == 0 && m_channel.isClosed(),
                                 "Only return zero if channel is closed");
        
        return returned;
    }

    final void write(const(ubyte)* buf, size_t len) { m_channel.send(buf, len); }

    final TLSChannel underlyingChannel() const { return m_channel; }
    final TLSChannel underlyingChannel() { return m_channel; }

    final void close() { m_channel.close(); }

    final bool isClosed() const { return m_channel.isClosed(); }

    final X509Certificate[] peerCertChain() const
    { return m_channel.peerCertChain(); }

    ~this() {}

protected:
    /**
     * Can to get the handshake complete notification override
    */
    abstract bool handshakeComplete(in TLSSession) { return true; }

    /**
    * Can to get notification of alerts override
    */
    abstract void alertNotification(in TLSAlert) {}

private:

    final bool handshakeCb(in TLSSession session)
    {
        return this.handshakeComplete(session);
    }

    final void dataCb(in ubyte[] data)
    {
        m_plaintext.insert(m_plaintext.end(), data.ptr, data.length);
    }

    final void alertCb(in TLSAlert alert, in ubyte[])
    {
        this.alertNotification(alert);
    }

    size_t delegate(ref ubyte[]) m_read_fn;
    TLSClient m_channel;
    Secure_Deque!ubyte m_plaintext;
}