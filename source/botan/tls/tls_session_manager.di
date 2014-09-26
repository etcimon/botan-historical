/*
* TLS Session Manager
* (C) 2011 Jack Lloyd
*
* Released under the terms of the botan license.
*/

#include <botan/tls_session.h>
#include <mutex>
#include <chrono>
#include <map>
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
		abstract bool load_from_session_id(in Vector!byte session_id,
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
		abstract void remove_entry(in Vector!byte session_id);

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
		abstract std::chrono::seconds session_lifetime() const;

		abstract ~Session_Manager() {}
};

/**
* An implementation of Session_Manager that does not save sessions at
* all, preventing session resumption.
*/
class Session_Manager_Noop : public Session_Manager
{
	public:
		bool load_from_session_id(in Vector!byte, Session&) override
		{ return false; }

		bool load_from_server_info(in Server_Information, Session&) override
		{ return false; }

		void remove_entry(in Vector!byte) override {}

		void save(in Session) override {}

		std::chrono::seconds session_lifetime() const override
		{ return std::chrono::seconds(0); }
};

/**
* An implementation of Session_Manager that saves values in memory.
*/
class Session_Manager_In_Memory : public Session_Manager
{
	public:
		/**
		* @param max_sessions a hint on the maximum number of sessions
		*		  to keep in memory at any one time. (If zero, don't cap)
		* @param session_lifetime sessions are expired after this many
		*		  seconds have elapsed from initial handshake.
		*/
		Session_Manager_In_Memory(RandomNumberGenerator& rng,
										  size_t max_sessions = 1000,
										  std::chrono::seconds session_lifetime =
											  std::chrono::seconds(7200));

		bool load_from_session_id(in Vector!byte session_id,
										  Session& session) override;

		bool load_from_server_info(in Server_Information info,
											Session& session) override;

		void remove_entry(in Vector!byte session_id) override;

		void save(in Session session_data) override;

		std::chrono::seconds session_lifetime() const override
		{ return m_session_lifetime; }

	private:
		bool load_from_session_str(in string session_str,
											Session& session);

		std::mutex m_mutex;

		size_t m_max_sessions;

		std::chrono::seconds m_session_lifetime;

		RandomNumberGenerator& m_rng;
		SymmetricKey m_session_key;

		std::map<string, Vector!( byte )> m_sessions; // hex(session_id) -> session
		std::map<Server_Information, string> m_info_sessions;
};

}