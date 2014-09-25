/*
* SCAN Name Abstraction
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/types.h>
#include <string>
#include <vector>
#include <mutex>
#include <map>
/**
A class encapsulating a SCAN name (similar to JCE conventions)
http://www.users.zetnet.co.uk/hopwood/crypto/scan/
*/
class SCAN_Name
{
	public:
		/**
		* @param algo_spec A SCAN-format name
		*/
		SCAN_Name(string algo_spec);

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
		string algo_name_and_args() const;

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
		string arg(size_t i) const;

		/**
		* @param i which argument
		* @param def_value the default value
		* @return ith argument or the default value
		*/
		string arg(size_t i, in string def_value) const;

		/**
		* @param i which argument
		* @param def_value the default value
		* @return ith argument as an integer, or the default value
		*/
		size_t arg_as_integer(size_t i, size_t def_value) const;

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

		static void add_alias(in string alias, in string basename);

		static string deref_alias(in string alias);

		static void set_default_aliases();
	private:
		static std::mutex s_alias_map_mutex;
		static std::map<string, string> s_alias_map;

		string orig_algo_spec;
		string alg_name;
		Vector!( string ) args;
		Vector!( string ) mode_info;
};