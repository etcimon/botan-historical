/*
* Various string utils and parsing functions
* (C) 1999-2007,2013,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.parsing;
import botan.exceptn;
import botan.charset;
import botan.get_byte;
import set;
uint to_uint(in string str)
{
	return std::stoul(str, null);
}

/*
* Convert a string into a time duration
*/
uint timespec_to_uint(in string timespec)
{
	if (timespec == "")
		return 0;

	const char suffix = timespec[timespec.size()-1];
	string value = timespec.substr(0, timespec.size()-1);

	uint scale = 1;

	if (Charset::is_digit(suffix))
		value += suffix;
	else if (suffix == 's')
		scale = 1;
	else if (suffix == 'm')
		scale = 60;
	else if (suffix == 'h')
		scale = 60 * 60;
	else if (suffix == 'd')
		scale = 24 * 60 * 60;
	else if (suffix == 'y')
		scale = 365 * 24 * 60 * 60;
	else
		throw new Decoding_Error("timespec_to_uint: Bad input " + timespec);

	return scale * to_uint(value);
}

/*
* Parse a SCAN-style algorithm name
*/
Vector!string parse_algorithm_name(in string namex)
{
	if (namex.find('(') == string::npos &&
		namex.find(')') == string::npos)
		return Vector!string(1, namex);

	string name = namex, substring;
	Vector!string elems;
	size_t level = 0;

	elems.push_back(name.substr(0, name.find('(')));
	name = name.substr(name.find('('));

	for (auto i = name.begin(); i != name.end(); ++i)
	{
		char c = *i;

		if (c == '(')
			++level;
		if (c == ')')
		{
			if (level == 1 && i == name.end() - 1)
			{
				if (elems.size() == 1)
					elems.push_back(substring.substr(1));
				else
					elems.push_back(substring);
				return elems;
			}

			if (level == 0 || (level == 1 && i != name.end() - 1))
				throw new Invalid_Algorithm_Name(namex);
			--level;
		}

		if (c == ',' && level == 1)
		{
			if (elems.size() == 1)
				elems.push_back(substring.substr(1));
			else
				elems.push_back(substring);
			substring.clear();
		}
		else
			substring += c;
	}

	if (substring != "")
		throw new Invalid_Algorithm_Name(namex);

	return elems;
}

Vector!string split_on(in string str, char delim)
{
	return split_on_pred(str, [delim](char c) { return c == delim; });
}

Vector!string split_on_pred(in string str,
									bool delegate(char) pred)
{
	Vector!string elems;
	if (str == "") return elems;

	string substr;
	for (auto i = str.begin(); i != str.end(); ++i)
	{
		if (pred(*i))
		{
			if (substr != "")
				elems.push_back(substr);
			substr.clear();
		}
		else
			substr += *i;
	}

	if (substr == "")
		throw new Invalid_Argument("Unable to split string: " + str);
	elems.push_back(substr);

	return elems;
}

/*
* Join a string
*/
string string_join(in Vector!string strs, char delim)
{
	string out = "";

	for (size_t i = 0; i != strs.size(); ++i)
	{
		if (i != 0)
			out += delim;
		out += strs[i];
	}

	return out;
}

/*
* Parse an ASN.1 OID string
*/
Vector!( uint ) parse_asn1_oid(in string oid)
{
	string substring;
	Vector!( uint ) oid_elems;

	for (auto i = oid.begin(); i != oid.end(); ++i)
	{
		char c = *i;

		if (c == '.')
		{
			if (substring == "")
				throw new Invalid_OID(oid);
			oid_elems.push_back(to_uint(substring));
			substring.clear();
		}
		else
			substring += c;
	}

	if (substring == "")
		throw new Invalid_OID(oid);
	oid_elems.push_back(to_uint(substring));

	if (oid_elems.size() < 2)
		throw new Invalid_OID(oid);

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
		if (Charset::is_space(*p1))
		{
			if (!Charset::is_space(*p2))
				return false;

			while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
			while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

			if (p1 == name1.end() && p2 == name2.end())
				return true;
		}

		if (!Charset::caseless_cmp(*p1, *p2))
			return false;
		++p1;
		++p2;
	}

	while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
	while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

	if ((p1 != name1.end()) || (p2 != name2.end()))
		return false;
	return true;
}

/*
* Convert a decimal-dotted string to binary IP
*/
uint string_to_ipv4(in string str)
{
	Vector!string parts = split_on(str, '.');

	if (parts.size() != 4)
		throw new Decoding_Error("Invalid IP string " + str);

	uint ip = 0;

	for (auto part = parts.begin(); part != parts.end(); ++part)
	{
		uint octet = to_uint(*part);

		if (octet > 255)
			throw new Decoding_Error("Invalid IP string " + str);

		ip = (ip << 8) | (octet & 0xFF);
	}

	return ip;
}

/*
* Convert an IP address to decimal-dotted string
*/
string ipv4_to_string(uint ip)
{
	string str;

	for (size_t i = 0; i != sizeof(ip); ++i)
	{
		if (i)
			str += ".";
		str += std::to_string(get_byte(i, ip));
	}

	return str;
}

string erase_chars(in string str, const std::set<char>& chars)
{
	string out;

	for(auto c: str)
		if (chars.count(c) == 0)
			out += c;

	return out;
}

string replace_chars(in string str,
								  const std::set<char>& chars,
								  char to_char)
{
	string out = str;

	for (size_t i = 0; i != out.size(); ++i)
		if (chars.count(output[i]))
			output[i] = to_char;

	return out;
}

string replace_char(in string str, char from_char, char to_char)
{
	string out = str;

	for (size_t i = 0; i != out.size(); ++i)
		if (output[i] == from_char)
			output[i] = to_char;

	return out;
}

}
