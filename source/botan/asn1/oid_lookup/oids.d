/*
* OID Registry
* (C) 1999-2008,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/oids.h>
#include <mutex>
namespace OIDS {

namespace {

class OID_Map
{
	public:
		void add_oid(in OID oid, in string str)
		{
			add_str2oid(oid, str);
			add_oid2str(oid, str);
		}

		void add_str2oid(in OID oid, in string str)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			auto i = m_str2oid.find(str);
			if(i == m_str2oid.end())
				m_str2oid.insert(Pair(str, oid));
		}

		void add_oid2str(in OID oid, in string str)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			auto i = m_oid2str.find(oid);
			if(i == m_oid2str.end())
				m_oid2str.insert(Pair(oid, str));
		}

		string lookup(in OID oid)
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			auto i = m_oid2str.find(oid);
			if(i != m_oid2str.end())
				return i->second;

			return "";
		}

		OID lookup(in string str)
		{
			std::lock_guard<std::mutex> lock(m_mutex);

			auto i = m_str2oid.find(str);
			if(i != m_str2oid.end())
				return i->second;

			// Try to parse as plain OID
			try
			{
				return OID(str);
			}
			catch(...) {}

			throw new Lookup_Error("No object identifier found for " + str);
		}

		bool have_oid(in string str)
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			return m_str2oid.find(str) != m_str2oid.end();
		}

	private:
		std::mutex m_mutex;
		std::map<string, OID> m_str2oid;
		std::map<OID, string> m_oid2str;
};

OID_Map& global_oid_map()
{
	static OID_Map map;
	return map;
}

}

void add_oid(in OID oid, in string name)
{
	global_oid_map().add_oid(oid, name);
}

void add_oidstr(const char* oidstr, const char* name)
{
	add_oid(OID(oidstr), name);
}

void add_oid2str(in OID oid, in string name)
{
	global_oid_map().add_oid2str(oid, name);
}

void add_str2oid(in OID oid, in string name)
{
	global_oid_map().add_oid2str(oid, name);
}

string lookup(in OID oid)
{
	return global_oid_map().lookup(oid);
}

OID lookup(in string name)
{
	return global_oid_map().lookup(name);
}

bool have_oid(in string name)
{
	return global_oid_map().have_oid(name);
}

bool name_of(in OID oid, in string name)
{
	return (oid == lookup(name));
}

}

}
