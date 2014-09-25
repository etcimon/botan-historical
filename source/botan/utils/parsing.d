/*
* Various string utils and parsing functions
* (C) 1999-2007,2013,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/parsing.h>
#include <botan/exceptn.h>
#include <botan/charset.h>
#include <botan/get_byte.h>
#include <set>

namespace Botan {

u32bit to_u32bit(in string str)
	{
	return std::stoul(str, nullptr);
	}

/*
* Convert a string into a time duration
*/
u32bit timespec_to_u32bit(in string timespec)
	{
	if(timespec == "")
		return 0;

	const char suffix = timespec[timespec.size()-1];
	string value = timespec.substr(0, timespec.size()-1);

	u32bit scale = 1;

	if(Charset::is_digit(suffix))
		value += suffix;
	else if(suffix == 's')
		scale = 1;
	else if(suffix == 'm')
		scale = 60;
	else if(suffix == 'h')
		scale = 60 * 60;
	else if(suffix == 'd')
		scale = 24 * 60 * 60;
	else if(suffix == 'y')
		scale = 365 * 24 * 60 * 60;
	else
		throw Decoding_Error("timespec_to_u32bit: Bad input " + timespec);

	return scale * to_u32bit(value);
	}

/*
* Parse a SCAN-style algorithm name
*/
std::vector<string> parse_algorithm_name(in string namex)
	{
	if(namex.find('(') == string::npos &&
		namex.find(')') == string::npos)
		return std::vector<string>(1, namex);

	string name = namex, substring;
	std::vector<string> elems;
	size_t level = 0;

	elems.push_back(name.substr(0, name.find('(')));
	name = name.substr(name.find('('));

	for(auto i = name.begin(); i != name.end(); ++i)
		{
		char c = *i;

		if(c == '(')
			++level;
		if(c == ')')
			{
			if(level == 1 && i == name.end() - 1)
				{
				if(elems.size() == 1)
					elems.push_back(substring.substr(1));
				else
					elems.push_back(substring);
				return elems;
				}

			if(level == 0 || (level == 1 && i != name.end() - 1))
				throw Invalid_Algorithm_Name(namex);
			--level;
			}

		if(c == ',' && level == 1)
			{
			if(elems.size() == 1)
				elems.push_back(substring.substr(1));
			else
				elems.push_back(substring);
			substring.clear();
			}
		else
			substring += c;
		}

	if(substring != "")
		throw Invalid_Algorithm_Name(namex);

	return elems;
	}

std::vector<string> split_on(in string str, char delim)
	{
	return split_on_pred(str, [delim](char c) { return c == delim; });
	}

std::vector<string> split_on_pred(in string str,
													std::function<bool (char)> pred)
	{
	std::vector<string> elems;
	if(str == "") return elems;

	string substr;
	for(auto i = str.begin(); i != str.end(); ++i)
		{
		if(pred(*i))
			{
			if(substr != "")
				elems.push_back(substr);
			substr.clear();
			}
		else
			substr += *i;
		}

	if(substr == "")
		throw Invalid_Argument("Unable to split string: " + str);
	elems.push_back(substr);

	return elems;
	}

/*
* Join a string
*/
string string_join(const std::vector<string>& strs, char delim)
	{
	string out = "";

	for(size_t i = 0; i != strs.size(); ++i)
		{
		if(i != 0)
			out += delim;
		out += strs[i];
		}

	return out;
	}

/*
* Parse an ASN.1 OID string
*/
std::vector<u32bit> parse_asn1_oid(in string oid)
	{
	string substring;
	std::vector<u32bit> oid_elems;

	for(auto i = oid.begin(); i != oid.end(); ++i)
		{
		char c = *i;

		if(c == '.')
			{
			if(substring == "")
				throw Invalid_OID(oid);
			oid_elems.push_back(to_u32bit(substring));
			substring.clear();
			}
		else
			substring += c;
		}

	if(substring == "")
		throw Invalid_OID(oid);
	oid_elems.push_back(to_u32bit(substring));

	if(oid_elems.size() < 2)
		throw Invalid_OID(oid);

	return oid_elems;
	}

/*
* X.500 String Comparison
*/
bool x500_name_cmp(in string name1, in string name2)
	{
	auto p1 = name1.begin();
	auto p2 = name2.begin();

	while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
	while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

	while(p1 != name1.end() && p2 != name2.end())
		{
		if(Charset::is_space(*p1))
			{
			if(!Charset::is_space(*p2))
				return false;

			while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
			while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

			if(p1 == name1.end() && p2 == name2.end())
				return true;
			}

		if(!Charset::caseless_cmp(*p1, *p2))
			return false;
		++p1;
		++p2;
		}

	while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
	while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

	if((p1 != name1.end()) || (p2 != name2.end()))
		return false;
	return true;
	}

/*
* Convert a decimal-dotted string to binary IP
*/
u32bit string_to_ipv4(in string str)
	{
	std::vector<string> parts = split_on(str, '.');

	if(parts.size() != 4)
		throw Decoding_Error("Invalid IP string " + str);

	u32bit ip = 0;

	for(auto part = parts.begin(); part != parts.end(); ++part)
		{
		u32bit octet = to_u32bit(*part);

		if(octet > 255)
			throw Decoding_Error("Invalid IP string " + str);

		ip = (ip << 8) | (octet & 0xFF);
		}

	return ip;
	}

/*
* Convert an IP address to decimal-dotted string
*/
string ipv4_to_string(u32bit ip)
	{
	string str;

	for(size_t i = 0; i != sizeof(ip); ++i)
		{
		if(i)
			str += ".";
		str += std::to_string(get_byte(i, ip));
		}

	return str;
	}

string erase_chars(in string str, const std::set<char>& chars)
	{
	string out;

	for(auto c: str)
		if(chars.count(c) == 0)
			out += c;

	return out;
	}

string replace_chars(in string str,
								  const std::set<char>& chars,
								  char to_char)
	{
	string out = str;

	for(size_t i = 0; i != out.size(); ++i)
		if(chars.count(out[i]))
			out[i] = to_char;

	return out;
	}

string replace_char(in string str, char from_char, char to_char)
	{
	string out = str;

	for(size_t i = 0; i != out.size(); ++i)
		if(out[i] == from_char)
			out[i] = to_char;

	return out;
	}

}
