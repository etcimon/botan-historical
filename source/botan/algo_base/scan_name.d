/*
* SCAN Name Abstraction
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/
module botan.algo_base.scan_name;

import botan.parsing;
import botan.utils.exceptn;
import stdexcept;
import botan.utils.types;
import string;
import vector;
import core.sync.mutex;
import map;

/**
A class encapsulating a SCAN name (similar to JCE conventions)
http://www.users.zetnet.co.uk/hopwood/crypto/scan/
*/
struct SCAN_Name
{
public:
	/**
	* @param algo_spec A SCAN-format name
	*/
	this(string algo_spec)
	{
		orig_algo_spec = algo_spec;
		
		Vector!( Tuple!(size_t, string)  ) name;
		size_t level = 0;
		Pair!(size_t, string) accum = Pair(level, "");
		
		string decoding_error = "Bad SCAN name '" ~ algo_spec ~ "': ";
		
		algo_spec = deref_alias(algo_spec);
		
		for (size_t i = 0; i != algo_spec.size(); ++i)
		{
			char c = algo_spec[i];
			
			if (c == '/' || c == ',' || c == '(' || c == ')')
			{
				if (c == '(')
					++level;
				else if (c == ')')
				{
					if (level == 0)
						throw new Decoding_Error(decoding_error ~ "Mismatched parens");
					--level;
				}
				
				if (c == '/' && level > 0)
					accum.second.push_back(c);
				else
				{
					if (accum.second != "")
						name.push_back(deref_aliases(accum));
					accum = Pair(level, "");
				}
			}
			else
				accum.second.push_back(c);
		}
		
		if (accum.second != "")
			name.push_back(deref_aliases(accum));
		
		if (level != 0)
			throw new Decoding_Error(decoding_error ~ "Missing close paren");
		
		if (name.size() == 0)
			throw new Decoding_Error(decoding_error ~ "Empty name");
		
		alg_name = name[0].second;
		
		bool in_modes = false;
		
		for (size_t i = 1; i != name.size(); ++i)
		{
			if (name[i].first == 0)
			{
				mode_info.push_back(make_arg(name, i));
				in_modes = true;
			}
			else if (name[i].first == 1 && !in_modes)
				args.push_back(make_arg(name, i));
		}
	}
	
	/**
	* @return original input string
	*/
	string as_string() const { return orig_algo_spec; }
	
	/**
	* @return algorithm name
	*/
	string algo_name() const { return alg_name; }
	
	/**
	* @return algorithm name plus any arguments
	*/
	string algo_name_and_args() const
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
	
	/**
	* @return number of arguments
	*/
	size_t arg_count() const { return args.size(); }
	
	/**
	* @param lower is the lower bound
	* @param upper is the upper bound
	* @return if the number of arguments is between lower and upper
	*/
	bool arg_count_between(size_t lower, size_t upper) const
	{ return ((arg_count() >= lower) && (arg_count() <= upper)); }
	
	/**
	* @param i which argument
	* @return ith argument
	*/
	string arg(size_t i) const
	{
		if (i >= arg_count())
			throw new std::range_error("SCAN_Name::argument - i out of range");
		return args[i];
	}
	
	/**
	* @param i which argument
	* @param def_value the default value
	* @return ith argument or the default value
	*/
	string arg(size_t i, in string def_value) const
	{
		if (i >= arg_count())
			return def_value;
		return args[i];
	}
	
	/**
	* @param i which argument
	* @param def_value the default value
	* @return ith argument as an integer, or the default value
	*/
	size_t arg_as_integer(size_t i, size_t def_value) const
	{
		if (i >= arg_count())
			return def_value;
		return to_uint(args[i]);
	}
	
	/**
	* @return cipher mode (if any)
	*/
	string cipher_mode() const
	{ return (mode_info.size() >= 1) ? mode_info[0] : ""; }
	
	/**
	* @return cipher mode padding (if any)
	*/
	string cipher_mode_pad() const
	{ return (mode_info.size() >= 2) ? mode_info[1] : ""; }
	
	static void add_alias(in string _alias, in string basename)
	{
		s_alias_map_mutex.lock(); scope(exit) s_alias_map_mutex.unlock();
		
		if (s_alias_map.find(_alias) == s_alias_map.end())
			s_alias_map[_alias] = basename;
	}

	
	static string deref_aliases(in Pair!(size_t, string) input)
	{
		return Pair(input.first, deref_alias(input.second));
	}

	static string deref_alias(in string _alias)
	{
		s_alias_map_mutex.lock(); scope(exit) s_alias_map_mutex.unlock();
		
		string name = _alias;
		
		for (auto i = s_alias_map.find(name); i != s_alias_map.end(); i = s_alias_map.find(name))
			name = i.second;
		
		return name;
	}

	static void set_default_aliases()
	{
		// common variations worth supporting
		add_alias("EME-PKCS1-v1_5",  "PKCS1v15");
		add_alias("3DES",	  "TripleDES");
		add_alias("DES-EDE",  "TripleDES");
		add_alias("CAST5",	 "CAST-128");
		add_alias("SHA1",	  "SHA-160");
		add_alias("SHA-1",	 "SHA-160");
		add_alias("MARK-4",	"RC4(256)");
		add_alias("ARC4",	  "RC4");
		add_alias("OMAC",	  "CMAC");
			
		add_alias("EMSA-PSS",		  "PSSR");
		add_alias("PSS-MGF1",		  "PSSR");
		add_alias("EME-OAEP",		  "OAEP");
			
		add_alias("EMSA2",			  "EMSA_X931");
		add_alias("EMSA3",			  "EMSA_PKCS1");
		add_alias("EMSA-PKCS1-v1_5", "EMSA_PKCS1");
			
			// should be renamed in sources
		add_alias("X9.31",			  "EMSA2");
			
			// kept for compatability with old library versions
		add_alias("EMSA4",			  "PSSR");
		add_alias("EME1",				"OAEP");
			
			// probably can be removed
		add_alias("GOST",	  "GOST-28147-89");
		add_alias("GOST-34.11", "GOST-R-34.11-94");
	}
	

private:
	static Mutex s_alias_map_mutex;
	static HashMap!(string, string) s_alias_map;
	
	string orig_algo_spec;
	string alg_name;
	Vector!string args;
	Vector!string mode_info;
}

string make_arg(in Vector!(Pair!(size_t, string)) name, size_t start)
{
	string output = name[start].second;
	size_t level = name[start].first;
	
	size_t paren_depth = 0;
	
	foreach (i; start + 1 .. name.size())
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
			output += ")," ~ name[i].second;
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
	
	foreach (i; 0 .. paren_depth)
		output += ')';
	
	return output;
}


string make_arg(
	const Vector!(Pair!(size_t, string)) name, size_t start)
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
			output += ")," ~ name[i].second;
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

