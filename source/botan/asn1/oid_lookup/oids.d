/*
* OID Registry
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.oid_lookup.oids;

public import botan.asn1.oid_lookup.deflt;
import botan.asn1_oid;
import core.sync.mutex;

/**
* Register an OID to string mapping.
* @param oid the oid to register
* @param name the name to be associated with the oid
*/
void add_oid2str(in OID oid, in string name)
{
	global_oid_map().add_oid2str(oid, name);
}

void add_str2oid(in OID oid, in string name)
{
	global_oid_map().add_str2oid(oid, name);
}

void add_oidstr(string oidstr, string name)
{
	add_oid(OID(oidstr), name);
}


void add_oid(in OID oid, in string name)
{
	global_oid_map().add_oid(oid, name);
}

/**
* See if an OID exists in the internal table.
* @param oid the oid to check for
* @return true if the oid is registered
*/
bool have_oid(in string name)
{
	return global_oid_map().have_oid(name);
}

/**
* Resolve an OID
* @param oid the OID to look up
* @return name associated with this OID
*/
string lookup(in OID oid)
{
	return global_oid_map().lookup(oid);
}

/**
* Find the OID to a name. The lookup will be performed in the
* general OID section of the configuration.
* @param name the name to resolve
* @return OID associated with the specified name
*/
OID lookup(in string name)
{
	return global_oid_map().lookup(name);
}

/**
* Tests whether the specified OID stands for the specified name.
* @param oid the OID to check
* @param name the name to check
* @return true if the specified OID stands for the specified name
*/
bool name_of(in OID oid, in string name)
{
	return (oid == lookup(name));
}

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
		m_mutex.lock(); scope(exit) m_mutex.unlock();
		auto i = m_str2oid.find(str);
		if (i == m_str2oid.end())
			m_str2oid.insert(Pair(str, oid));
	}
	
	void add_oid2str(in OID oid, in string str)
	{
		m_mutex.lock(); scope(exit) m_mutex.unlock();
		auto i = m_oid2str.find(oid);
		if (i == m_oid2str.end())
			m_oid2str.insert(Pair(oid, str));
	}
	
	string lookup(in OID oid)
	{
		m_mutex.lock(); scope(exit) m_mutex.unlock();
		
		auto i = m_oid2str.find(oid);
		if (i != m_oid2str.end())
			return i.second;
		
		return "";
	}
	
	OID lookup(in string str)
	{
		m_mutex.lock(); scope(exit) m_mutex.unlock();
		
		auto i = m_str2oid.find(str);
		if (i != m_str2oid.end())
			return i.second;
		
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
		m_mutex.lock(); scope(exit) m_mutex.unlock();
		return m_str2oid.find(str) != m_str2oid.end();
	}
	
private:
	Mutex m_mutex;
	HashMap!(string, OID) m_str2oid;
	HashMap!(OID, string) m_oid2str;
};

ref OID_Map global_oid_map()
{
	static OID_Map map;
	return map;
}