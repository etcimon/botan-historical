/*
* SQLite wrapper
* (C) 2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/sqlite3.h>
#include <stdexcept>
#include <sqlite3.h>
sqlite3_database::sqlite3_database(in string db_filename)
{
	int rc = ::sqlite3_open(db_filename.c_str(), &m_db);

	if(rc)
	{
		const string err_msg = ::sqlite3_errmsg(m_db);
		::sqlite3_close(m_db);
		m_db = null;
		throw new Exception("sqlite3_open failed - " + err_msg);
	}
}

sqlite3_database::~sqlite3_database()
{
	if(m_db)
		::sqlite3_close(m_db);
	m_db = null;
}

size_t sqlite3_database::row_count(in string table_name)
{
	sqlite3_statement stmt(this, "select count(*) from " + table_name);

	if(stmt.step())
		return stmt.get_size_t(0);
	else
		throw new Exception("Querying size of table " + table_name + " failed");
}

void sqlite3_database::create_table(in string table_schema)
{
	char* errmsg = null;
	int rc = ::sqlite3_exec(m_db, table_schema.c_str(), null, null, &errmsg);

	if(rc != SQLITE_OK)
	{
		const string err_msg = errmsg;
		::sqlite3_free(errmsg);
		::sqlite3_close(m_db);
		m_db = null;
		throw new Exception("sqlite3_exec for table failed - " + err_msg);
	}
}sqlite3_statement::sqlite3_statement(sqlite3_database* db, in string base_sql)
{
	int rc = ::sqlite3_prepare_v2(db->m_db, base_sql.c_str(), -1, &m_stmt, null);

	if(rc != SQLITE_OK)
		throw new Exception("sqlite3_prepare failed " + base_sql +
										 ", code " + std::to_string(rc));
}

void sqlite3_statement::bind(int column, in string val)
{
	int rc = ::sqlite3_bind_text(m_stmt, column, val.c_str(), -1, SQLITE_TRANSIENT);
	if(rc != SQLITE_OK)
		throw new Exception("sqlite3_bind_text failed, code " + std::to_string(rc));
}

void sqlite3_statement::bind(int column, int val)
{
	int rc = ::sqlite3_bind_int(m_stmt, column, val);
	if(rc != SQLITE_OK)
		throw new Exception("sqlite3_bind_int failed, code " + std::to_string(rc));
}

void sqlite3_statement::bind(int column, SysTime time)
{
	const int timeval = std::chrono::duration_cast(<std::chrono::seconds>)(time.time_since_epoch()).count();
	bind(column, timeval);
}

void sqlite3_statement::bind(int column, in Vector!byte val)
{
	int rc = ::sqlite3_bind_blob(m_stmt, column, &val[0], val.size(), SQLITE_TRANSIENT);
	if(rc != SQLITE_OK)
		throw new Exception("sqlite3_bind_text failed, code " + std::to_string(rc));
}

Pair!(const byte*, size_t) sqlite3_statement::get_blob(int column)
{
	BOTAN_ASSERT(::sqlite3_column_type(m_stmt, 0) == SQLITE_BLOB,
					 "Return value is a blob");

	const void* session_blob = ::sqlite3_column_blob(m_stmt, column);
	const int session_blob_size = ::sqlite3_column_bytes(m_stmt, column);

	BOTAN_ASSERT(session_blob_size >= 0, "Blob size is non-negative");

	return Pair(cast(const byte*)(session_blob),
								 cast(size_t)(session_blob_size));
}

size_t sqlite3_statement::get_size_t(int column)
{
	BOTAN_ASSERT(::sqlite3_column_type(m_stmt, column) == SQLITE_INTEGER,
					 "Return count is an integer");

	const int sessions_int = ::sqlite3_column_int(m_stmt, column);

	BOTAN_ASSERT(sessions_int >= 0, "Expected size_t is non-negative");

	return cast(size_t)(sessions_int);
}

void sqlite3_statement::spin()
{
	while(step()) {}
}

bool sqlite3_statement::step()
{
	return (::sqlite3_step(m_stmt) == SQLITE_ROW);
}

sqlite3_statement::~sqlite3_statement()
{
	::sqlite3_finalize(m_stmt);
}

}
