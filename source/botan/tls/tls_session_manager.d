/*
* TLS Session Manager
* (C) 2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_session_manager;

public import botan.tls.tls_session;
public import botan.tls.tls_server_info;
public import botan.algo_base.sym_algo;
public import botan.rng.rng;
import botan.codec.hex;
import std.datetime;
import core.sync.mutex;
import std.datetime;
import botan.utils.hashmap;

/**
* Session_Manager is an interface to systems which can save
* session parameters for supporting session resumption.
*
* Saving sessions is done on a best-effort basis; an implementation is
* allowed to drop sessions due to space constraints.
*
* Implementations should strive to be thread safe
*/
class Session_Manager
{
public:
	/**
	* Try to load a saved session (using session ID)
	* @param session_id the session identifier we are trying to resume
	* @param session will be set to the saved session data (if found),
				or not modified if not found
	* @return true if session was modified
	*/
	abstract bool load_from_session_id(in Vector!ubyte session_id,
												 Session session);

	/**
	* Try to load a saved session (using info about server)
	* @param info the information about the server
	* @param session will be set to the saved session data (if found),
				or not modified if not found
	* @return true if session was modified
	*/
	abstract bool load_from_server_info(in Server_Information info,
												  Session session);

	/**
	* Remove this session id from the cache, if it exists
	*/
	abstract void remove_entry(in Vector!ubyte session_id);

	/**
	* Save a session on a best effort basis; the manager may not in
	* fact be able to save the session for whatever reason; this is
	* not an error. Caller cannot assume that calling save followed
	* immediately by load_from_* will result in a successful lookup.
	*
	* @param session to save
	*/
	abstract void save(in Session session);

	/**
	* Return the allowed lifetime of a session; beyond this time,
	* sessions are not resumed. Returns 0 if unknown/no explicit
	* expiration policy.
	*/
	abstract Duration session_lifetime() const;

	~this() {}
}

/**
* An implementation of Session_Manager that does not save sessions at
* all, preventing session resumption.
*/
final class Session_Manager_Noop : Session_Manager
{
public:
	override bool load_from_session_id(in Vector!ubyte, Session)
	{ return false; }

	override bool load_from_server_info(in Server_Information, Session)
	{ return false; }

	override void remove_entry(in Vector!ubyte) {}

	override void save(in Session) {}

	override Duration session_lifetime() const
	{ return Duration.init; }
}

/**
* An implementation of Session_Manager that saves values in memory.
*/
final class Session_Manager_In_Memory : Session_Manager
{
public:
	/**
	* @param max_sessions a hint on the maximum number of sessions
	*		  to keep in memory at any one time. (If zero, don't cap)
	* @param session_lifetime sessions are expired after this many
	*		  seconds have elapsed from initial handshake.
	*/
	this(RandomNumberGenerator rng,
			size_t max_sessions = 1000,
			Duration session_lifetime = 7200.seconds) 
	{
		m_max_sessions = max_sessions;
		m_session_lifetime = session_lifetime;
		m_rng = rng;
		m_session_key = SymmetricKey(m_rng, 32);
		
	}

	override bool load_from_session_id(
		in Vector!ubyte session_id, Session session)
	{
		
		return load_from_session_str(hex_encode(session_id), session);
	}

	override bool load_from_server_info(
		const Server_Information info, Session session)
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

	override void remove_entry(
		in Vector!ubyte session_id)
	{		
		auto i = m_sessions.find(hex_encode(session_id));
		
		if (i != m_sessions.end())
			m_sessions.erase(i);
	}

	override void save(in Session session)
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
		
		const string session_id_str = hex_encode(session.session_id());
		
		m_sessions[session_id_str] = session.encrypt(m_session_key, m_rng);
		
		if (session.side() == CLIENT && !session.server_info().empty)
			m_info_sessions[session.server_info()] = session_id_str;
	}

	override Duration session_lifetime() const
	{ return m_session_lifetime; }

private:
	bool load_from_session_str(in string session_str, Session session)
	{
		// assert(lock is held)
		
		auto i = m_sessions.find(session_str);
		
		if (i == m_sessions.end())
			return false;
		
		try
		{
			session = Session.decrypt(i.second, m_session_key);
		}
		catch
		{
			return false;
		}
		
		// if session has expired, remove it
		const auto now = Clock.currTime();
		
		if (session.start_time() + session_lifetime() < now)
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
	HashMap!(Server_Information, string) m_info_sessions;
}