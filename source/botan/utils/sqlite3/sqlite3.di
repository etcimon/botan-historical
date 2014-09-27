/*
* SQLite wrapper
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.types;
import string;
import chrono;
import vector;

class sqlite3;
class sqlite3_stmt;
class sqlite3_database
{
	public:
		sqlite3_database(in string file);

		~this();

		size_t row_count(in string table_name);

		void create_table(in string table_schema);
	private:
		friend class sqlite3_statement;

		sqlite3* m_db;
};

class sqlite3_statement
{
	public:
		sqlite3_statement(sqlite3_database* db,
								in string base_sql);

		void bind(int column, in string val);

		void bind(int column, int val);

		void bind(int column, SysTime time);

		void bind(int column, in Vector!byte val);

		Pair!(const byte*, size_t) get_blob(int column);

		size_t get_size_t(int column);

		void spin();

		bool step();

		sqlite3_stmt* stmt() { return m_stmt; }

		~this();
	private:
		sqlite3_stmt* m_stmt;
};