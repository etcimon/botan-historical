/*
* Various string utils and parsing functions
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_PARSER_H__

#include <botan/types.h>
#include <string>
#include <vector>
#include <set>

#include <istream>
#include <functional>
#include <map>
/**
* Parse a SCAN-style algorithm name
* @param scan_name the name
* @return the name components
*/
std::vector<string>
parse_algorithm_name(in string scan_name);

/**
* Split a string
* @param str the input string
* @param delim the delimitor
* @return string split by delim
*/
std::vector<string> split_on(
	in string str, char delim);

/**
* Split a string on a character predicate
* @param str the input string
*/
std::vector<string>
split_on_pred(in string str,
				  std::function<bool (char)> pred);

/**
* Erase characters from a string
*/
string erase_chars(in string str, const std::set<char>& chars);

/**
* Replace a character in a string
* @param str the input string
* @param from_char the character to replace
* @param to_char the character to replace it with
* @return str with all instances of from_char replaced by to_char
*/
string replace_char(in string str,
											  char from_char,
											  char to_char);

/**
* Replace a character in a string
* @param str the input string
* @param from_chars the characters to replace
* @param to_char the character to replace it with
* @return str with all instances of from_chars replaced by to_char
*/
string replace_chars(in string str,
												const std::set<char>& from_chars,
												char to_char);

/**
* Join a string
* @param strs strings to join
* @param delim the delimitor
* @return string joined by delim
*/
string string_join(const std::vector<string>& strs,
											 char delim);

/**
* Parse an ASN.1 OID
* @param oid the OID in string form
* @return OID components
*/
std::vector<u32bit> parse_asn1_oid(in string oid);

/**
* Compare two names using the X.509 comparison algorithm
* @param name1 the first name
* @param name2 the second name
* @return true if name1 is the same as name2 by the X.509 comparison rules
*/
bool x500_name_cmp(in string name1,
									  in string name2);

/**
* Convert a string to a number
* @param str the string to convert
* @return number value of the string
*/
u32bit to_u32bit(in string str);

/**
* Convert a time specification to a number
* @param timespec the time specification
* @return number of seconds represented by timespec
*/
u32bit timespec_to_u32bit(in string timespec);

/**
* Convert a string representation of an IPv4 address to a number
* @param ip_str the string representation
* @return integer IPv4 address
*/
u32bit string_to_ipv4(in string ip_str);

/**
* Convert an IPv4 address to a string
* @param ip_addr the IPv4 address to convert
* @return string representation of the IPv4 address
*/
string ipv4_to_string(u32bit ip_addr);

void lex_cfg(std::istream& is,
							  std::function<void (string)> cb);

void lex_cfg_w_headers(std::istream& is,
											std::function<void (string)> cb,
											std::function<void (string)> header_cb);

std::map<string, std::map<string, string>>
BOTAN_DLL
parse_cfg(std::istream& is);
