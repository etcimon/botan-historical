/*
* SCAN Name Abstraction
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.scan_name;
import botan.parsing;
import botan.exceptn;
import stdexcept;

string make_arg(
	const Vector!(ref Pair!(size_t, string)  ) name, size_t start)
{
	string output = name[start].second;
	size_t level = name[start].first;

	size_t paren_depth = 0;

	for (size_t i = start + 1; i != name.size(); ++i)
	{
		if (name[i].first <= name[start].first)
			break;

		if (name[i].first > level)
		{
			output += '(' + name[i].second;
			++paren_depth;
		}
		else if (name[i].first < level)
		{
			output += ")," + name[i].second;
			--paren_depth;
		}
		else
		{
			if (output[output.size() - 1] != '(')
				output += ",";
			output += name[i].second;
		}

		level = name[i].first;
	}

	for (size_t i = 0; i != paren_depth; ++i)
		output += ')';

	return output;
}

Pair!(size_t, string)
deref_aliases(in Pair!(size_t, string) input)
{
	return Pair(input.first,
								 SCAN_Name::deref_alias(input.second));
}

}

std::mutex SCAN_Name::s_alias_map_mutex;
HashMap!(string, string) SCAN_Name::s_alias_map;


string SCAN_Name::algo_name_and_args() const
{
	string output;

	output = algo_name();

	if (arg_count())
	{
		output += '(';
		for (size_t i = 0; i != arg_count(); ++i)
		{
			output += arg(i);
			if (i != arg_count() - 1)
				output += ',';
		}
		output += ')';

	}

	return output;
}

string SCAN_Name::arg(size_t i) const
{
	if (i >= arg_count())
		throw new std::range_error("SCAN_Name::argument - i out of range");
	return args[i];
}

string SCAN_Name::arg(size_t i, in string def_value) const
{
	if (i >= arg_count())
		return def_value;
	return args[i];
}

size_t SCAN_Name::arg_as_integer(size_t i, size_t def_value) const
{
	if (i >= arg_count())
		return def_value;
	return to_uint(args[i]);
}

void SCAN_Name::add_alias(in string _alias, in string basename)
{
	std::lock_guard<std::mutex> lock(s_alias_map_mutex);

	if (s_alias_map.find(_alias) == s_alias_map.end())
		s_alias_map[_alias] = basename;
}

string SCAN_Name::deref_alias(in string _alias)
{
	std::lock_guard<std::mutex> lock(s_alias_map_mutex);

	string name = _alias;

	for (auto i = s_alias_map.find(name); i != s_alias_map.end(); i = s_alias_map.find(name))
		name = i->second;

	return name;
}

void SCAN_Name::set_default_aliases()
{
	// common variations worth supporting
	SCAN_Name::add_alias("EME-PKCS1-v1_5",  "PKCS1v15");
	SCAN_Name::add_alias("3DES",	  "TripleDES");
	SCAN_Name::add_alias("DES-EDE",  "TripleDES");
	SCAN_Name::add_alias("CAST5",	 "CAST-128");
	SCAN_Name::add_alias("SHA1",	  "SHA-160");
	SCAN_Name::add_alias("SHA-1",	 "SHA-160");
	SCAN_Name::add_alias("MARK-4",	"RC4(256)");
	SCAN_Name::add_alias("ARC4",	  "RC4");
	SCAN_Name::add_alias("OMAC",	  "CMAC");

	SCAN_Name::add_alias("EMSA-PSS",		  "PSSR");
	SCAN_Name::add_alias("PSS-MGF1",		  "PSSR");
	SCAN_Name::add_alias("EME-OAEP",		  "OAEP");

	SCAN_Name::add_alias("EMSA2",			  "EMSA_X931");
	SCAN_Name::add_alias("EMSA3",			  "EMSA_PKCS1");
	SCAN_Name::add_alias("EMSA-PKCS1-v1_5", "EMSA_PKCS1");

	// should be renamed in sources
	SCAN_Name::add_alias("X9.31",			  "EMSA2");

	// kept for compatability with old library versions
	SCAN_Name::add_alias("EMSA4",			  "PSSR");
	SCAN_Name::add_alias("EME1",				"OAEP");

	// probably can be removed
	SCAN_Name::add_alias("GOST",	  "GOST-28147-89");
	SCAN_Name::add_alias("GOST-34.11", "GOST-R-34.11-94");
}

