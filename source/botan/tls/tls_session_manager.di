/*
* TLS Session Manager
* (C) 2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.tls_session;
import core.sync.mutex;
import std.datetime;
import map;
namespace TLS {

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
													 Session& session);

		/**
		* Try to load a saved session (using info about server)
		* @param info the information about the server
		* @param session will be set to the saved session data (if found),
					or not modified if not found
		* @return true if session was modified
		*/
		abstract bool load_from_server_info(in Server_Information info,
													  Session& session);

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
};

/**
* An implementation of Session_Manager that does not save sessions at
* all, preventing session resumption.
*/
class Session_Manager_Noop : Session_Manager
{
	public:
		override bool load_from_session_id(in Vector!ubyte, Session&)
		{ return false; }

		override bool load_from_server_info(in Server_Information, Session&)
		{ return false; }

		override void remove_entry(in Vector!ubyte) {}

		override void save(in Session) {}

		override Duration session_lifetime() const
		{ return Duration.init; }
};

/**
* An implementation of Session_Manager that saves values in memory.
*/
class Session_Manager_In_Memory : Session_Manager
{
	public:
		/**
		* @param max_sessions a hint on the maximum number of sessions
		*		  to keep in memory at any one time. (If zero, don't cap)
		* @param session_lifetime sessions are expired after this many
		*		  seconds have elapsed from initial handshake.
		*/
		Session_Manager_In_Memory(RandomNumberGenerator rng,
										  size_t max_sessions = 1000,
										  Duration session_lifetime =
											  TickDuration.from!"seconds"(7200).to!Duration);

		bool load_from_session_id(in Vector!ubyte session_id,
										  override Session& session);

		bool load_from_server_info(in Server_Information info,
											override Session& session);

		override void remove_entry(in Vector!ubyte session_id);

		override void save(in Session session_data);

		override Duration session_lifetime() const
		{ return m_session_lifetime; }

	private:
		bool load_from_session_str(in string session_str,
											Session& session);

		Mutex m_mutex;

		size_t m_max_sessions;

		Duration m_session_lifetime;

		RandomNumberGenerator m_rng;
		SymmetricKey m_session_key;

		HashMap<string, Vector!ubyte> m_sessions; // hex(session_id) . session
		HashMap<Server_Information, string> m_info_sessions;
};

}