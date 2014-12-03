/*
* TLS TLSSession Manager
* (C) 2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.session_manager;

import botan.constants;
static if (BOTAN_HAS_TLS):

public import botan.tls.session;
public import botan.tls.server_info;
public import botan.algo_base.sym_algo;
public import botan.rng.rng;
import botan.codec.hex;
import std.datetime;
import core.sync.mutex;
import std.datetime;
import botan.utils.containers.hashmap;

/**
* TLS_Session_Manager is an interface to systems which can save
* session parameters for supporting session resumption.
*
* Saving sessions is done on a best-effort basis; an implementation is
* allowed to drop sessions due to space constraints.
*
* Implementations should strive to be thread safe
*/
class TLSSessionManager
{
public:
    /**
    * Try to load a saved session (using session ID)
    * @param session_id = the session identifier we are trying to resume
    * @param session = will be set to the saved session data (if found),
                or not modified if not found
    * @return true if session was modified
    */
    abstract bool loadFromSessionId(in Vector!ubyte session_id,
                                                 TLSSession session);

    /**
    * Try to load a saved session (using info about server)
    * @param info = the information about the server
    * @param session = will be set to the saved session data (if found),
                or not modified if not found
    * @return true if session was modified
    */
    abstract bool loadFromServerInfo(in TLSServerInformation info,
                                                  TLSSession session);

    /**
    * Remove this session id from the cache, if it exists
    */
    abstract void removeEntry(in Vector!ubyte session_id);

    /**
    * Save a session on a best effort basis; the manager may not in
    * fact be able to save the session for whatever reason; this is
    * not an error. Caller cannot assume that calling save followed
    * immediately by load_from_* will result in a successful lookup.
    *
    * @param session = to save
    */
    abstract void save(in TLSSession session);

    /**
    * Return the allowed lifetime of a session; beyond this time,
    * sessions are not resumed. Returns 0 if unknown/no explicit
    * expiration policy.
    */
    abstract Duration sessionLifetime() const;

    ~this() {}
}

/**
* An implementation of TLS_Session_Manager that does not save sessions at
* all, preventing session resumption.
*/
final class TLSSessionManagerNoop : TLS_Session_Manager
{
public:
    override bool loadFromSessionId(in Vector!ubyte, TLSSession)
    { return false; }

    override bool loadFromServerInfo(in TLSServerInformation, TLSSession)
    { return false; }

    override void removeEntry(in Vector!ubyte) {}

    override void save(in TLSSession) {}

    override Duration sessionLifetime() const
    { return Duration.init; }
}

/**
* An implementation of TLS_Session_Manager that saves values in memory.
*/
final class TLSSessionManagerInMemory : TLS_Session_Manager
{
public:
    /**
    * @param max_sessions = a hint on the maximum number of sessions
    *          to keep in memory at any one time. (If zero, don't cap)
    * @param session_lifetime = sessions are expired after this many
    *          seconds have elapsed from initial handshake.
    */
    this(RandomNumberGenerator rng, size_t max_sessions = 1000, Duration session_lifetime = 7200.seconds) 
    {
        m_max_sessions = max_sessions;
        m_session_lifetime = session_lifetime;
        m_rng = rng;
        m_session_key = SymmetricKey(m_rng, 32);
        
    }

    override bool loadFromSessionId(
        in Vector!ubyte session_id, TLSSession session)
    {
        
        return load_from_session_str(hexEncode(session_id), session);
    }

    override bool loadFromServerInfo(
        const TLSServerInformation info, TLSSession session)
    {
        
        auto i = m_info_sessions.find(info);
        
        if (i == m_info_sessions.end())
            return false;
        
        if (load_from_session_str(i.second, session))
            return true;
        
        /*
        * It existed at one point but was removed from the sessions map,
        * remove m_info_sessions entry as well
        */
        m_info_sessions.erase(i);
        
        return false;
    }

    override void removeEntry(in Vector!ubyte session_id)
    {        
        auto i = m_sessions.find(hexEncode(session_id));
        
        if (i != m_sessions.end())
            m_sessions.erase(i);
    }

    override void save(in TLSSession session)
    {
        
        if (m_max_sessions != 0)
        {
            /*
            We generate new session IDs with the first 4 bytes being a
            timestamp, so this actually removes the oldest sessions first.
            */
            while (m_sessions.length >= m_max_sessions)
                m_sessions.erase(m_sessions.ptr);
        }
        
        const string session_id_str = hexEncode(session.sessionId());
        
        m_sessions[session_id_str] = session.encrypt(m_session_key, m_rng);
        
        if (session.side() == CLIENT && !session.serverInfo().empty)
            m_info_sessions[session.serverInfo()] = session_id_str;
    }

    override Duration sessionLifetime() const
    { return m_session_lifetime; }

private:
    bool loadFromSessionStr(in string session_str, TLSSession session)
    {
        // assert(lock is held)
        
        auto i = m_sessions.find(session_str);
        
        if (i == m_sessions.end())
            return false;
        
        try
        {
            session = TLSSession.decrypt(i.second, m_session_key);
        }
        catch (Throwable)
        {
            return false;
        }
        
        // if session has expired, remove it
        const auto now = Clock.currTime();
        
        if (session.startTime() + session_lifetime() < now)
        {
            m_sessions.erase(i);
            return false;
        }
        
        return true;
    }

    size_t m_max_sessions;

    Duration m_session_lifetime;

    RandomNumberGenerator m_rng;
    SymmetricKey m_session_key;

    HashMap!(string, Vector!ubyte) m_sessions; // hex(session_id) . session
    HashMap!(TLSServerInformation, string) m_info_sessions;
}