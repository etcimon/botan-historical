/*
* SQLite3 TLS TLS_Session Manager
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.session_manager_sqlite;

import botan.constants;
static if (BOTAN_HAS_TLS):

import botan.tls.session_manager;
import botan.utils.sqlite3.sqlite3;
import botan.libstate.lookup;
import botan.codec.hex;
import botan.utils.loadstor;
import std.datetime;


/**
* An implementation of TLS_Session_Manager that saves values in a SQLite3
* database file, with the session data encrypted using a passphrase.
*
* @warning For clients, the hostnames associated with the saved
* sessions are stored in the database in plaintext. This may be a
* serious privacy risk in some situations.
*/
final class TLS_Session_Manager_SQLite : TLS_Session_Manager
{
public:
    /**
    * @param passphrase = used to encrypt the session data
    * @param rng = a random number generator
    * @param db_filename = filename of the SQLite database file.
                The table names tls_sessions and tls_sessions_metadata
                will be used
    * @param max_sessions = a hint on the maximum number of sessions
    *          to keep in memory at any one time. (If zero, don't cap)
    * @param session_lifetime = sessions are expired after this many
    *          seconds have elapsed from initial handshake.
    */
    this(in string passphrase,
           RandomNumberGenerator rng,
           in string db_filename,
           size_t max_sessions = 1000,
           Duration session_lifetime = 7200.seconds) 
    {
        m_rng = rng;
        m_max_sessions = max_sessions;
        m_session_lifetime = session_lifetime;
        m_db = new sqlite3_database(db_filename);

        m_db.create_table(
            "create table if not exists tls_sessions "
            ~ "("
            ~ "session_id TEXT PRIMARY KEY, "
            ~ "session_start INTEGER, "
            ~ "hostname TEXT, "
            ~ "hostport INTEGER, "
            ~ "session BLOB"
            ~ ")");
        
        m_db.create_table(
            "create table if not exists tls_sessions_metadata "
            ~ "("
            ~ "passphrase_salt BLOB, "
            ~ "passphrase_iterations INTEGER, "
            ~ "passphrase_check INTEGER "
            ~ ")");
        
        const size_t salts = m_db.row_count("tls_sessions_metadata");
        
        if (salts == 1)
        {
            // existing db
            sqlite3_statement stmt = sqlite3_statement(m_db, "select * from tls_sessions_metadata");
            
            if (stmt.step())
            {
                Pair!(const ubyte*, size_t) salt = stmt.get_blob(0);
                const size_t iterations = stmt.get_size_t(1);
                const size_t check_val_db = stmt.get_size_t(2);
                
                size_t check_val_created;
                m_session_key = derive_key(passphrase,
                                           salt.first,
                                           salt.second,
                                           iterations,
                                           check_val_created);
                
                if (check_val_created != check_val_db)
                    throw new Exception("TLS_Session database password not valid");
            }
        }
        else
        {
            // maybe just zap the salts + sessions tables in this case?
            if (salts != 0)
                throw new Exception("Seemingly corrupted database, multiple salts found");
            
            // new database case
            
            Vector!ubyte salt = unlock(rng.random_vec(16));
            const size_t iterations = 256 * 1024;
            size_t check_val = 0;
            
            m_session_key = derive_key(passphrase, salt.ptr, salt.length,
            iterations, check_val);
            
            sqlite3_statement stmt = sqlite3_statement(m_db, "insert into tls_sessions_metadata"
                                   ~ " values(?1, ?2, ?3)");
            
            stmt.bind(1, salt);
            stmt.bind(2, iterations);
            stmt.bind(3, check_val);
            
            stmt.spin();
        }
    }

    ~this()
    {
        delete m_db;
    }

    override bool load_from_session_id(in Vector!ubyte session_id, ref TLS_Session session)
    {
        sqlite3_statement stmt = sqlite3_statement(m_db, "select session from tls_sessions where session_id = ?1");
        
        stmt.bind(1, hex_encode(session_id));
        
        while (stmt.step())
        {
            Pair!(const ubyte*, size_t) blob = stmt.get_blob(0);
            
            try
            {
                session = TLS_Session.decrypt(blob.first, blob.second, m_session_key);
                return true;
            }
            catch (Throwable)
            {
            }
        }
        
        return false;
    }

    override bool load_from_server_info(in TLS_Server_Information server,
                                        ref TLS_Session session)
    {
        sqlite3_statement stmt = sqlite3_statement(m_db, "select session from tls_sessions"
                                                   ~ " where hostname = ?1 and hostport = ?2"
                                                   ~ " order by session_start desc");
        
        stmt.bind(1, server.hostname());
        stmt.bind(2, server.port());
        
        while (stmt.step())
        {
            Pair!(const ubyte*, size_t) blob = stmt.get_blob(0);
            
            try
            {
                session = TLS_Session.decrypt(blob.first, blob.second, m_session_key);
                return true;
            }
            catch (Throwable)
            {
            }
        }
        
        return false;
    }

    override void remove_entry(in Vector!ubyte session_id)
    {
        sqlite3_statement stmt = sqlite3_statement(m_db, "delete from tls_sessions where session_id = ?1");
        
        stmt.bind(1, hex_encode(session_id));
        
        stmt.spin();
    }

    override void save(in TLS_Session session)
    {
        sqlite3_statement stmt = sqlite3_statement(m_db, "insert or replace into tls_sessions"
                               ~ " values(?1, ?2, ?3, ?4, ?5)");
        
        stmt.bind(1, hex_encode(session.session_id()));
        stmt.bind(2, session.start_time());
        stmt.bind(3, session.server_info().hostname());
        stmt.bind(4, session.server_info().port());
        stmt.bind(5, session.encrypt(m_session_key, m_rng));
        
        stmt.spin();
        
        prune_session_cache();
    }

    override Duration session_lifetime() const
    { return m_session_lifetime; }

private:
    @disable this(in TLS_Session_Manager_SQLite);
    TLS_Session_Manager_SQLite opAssign(in TLS_Session_Manager_SQLite);

    void prune_session_cache()
    {
        sqlite3_statement remove_expired = sqlite3_statement(m_db, "delete from tls_sessions where session_start <= ?1");
        
        remove_expired.bind(1, Clock.currTime() - m_session_lifetime);
        
        remove_expired.spin();
        
        const size_t sessions = m_db.row_count("tls_sessions");
        
        if (sessions > m_max_sessions)
        {
            sqlite3_statement remove_some = sqlite3_statement(m_db, "delete from tls_sessions where session_id in "
                                          ~ "(select session_id from tls_sessions limit ?1)");
            
            remove_some.bind(1, sessions - m_max_sessions);
            remove_some.spin();
        }
    }

    SymmetricKey m_session_key;
    RandomNumberGenerator m_rng;
    size_t m_max_sessions;
    Duration m_session_lifetime;
    sqlite3_database m_db;
}

SymmetricKey derive_key(in string passphrase,
                        in ubyte* salt,
                        size_t salt_len,
                        size_t iterations,
                        ref size_t check_val)
{
    Unique!PBKDF pbkdf = get_pbkdf("PBKDF2(SHA-512)");
    
    Secure_Vector!ubyte x = pbkdf.derive_key(32 + 2,
                                          passphrase,
                                          salt, salt_len,
                                          iterations).bits_of();
    
    check_val = make_ushort(x[0], x[1]);
    return SymmetricKey(&x[2], x.length - 2);
}