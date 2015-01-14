/*
* Various string utils and parsing functions
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.parsing;
import botan.utils.types;
// import string;
import botan.utils.types;
import botan.utils.parsing;
import botan.utils.exceptn;
import botan.utils.charset;
import botan.utils.get_byte;
import botan.utils.containers.hashmap;
/**
* Parse a SCAN-style algorithm name
* @param scan_name = the name
* @return the name components
*/
/*
* Parse a SCAN-style algorithm name
*/
Vector!string parseAlgorithmName(in string scan_name)
{
    import std.array : Appender;
    if (scan_name.find('(') == -1 &&
        scan_name.find(')') == -1) {
        Vector!string str;
        str ~= scan_name;
        return str;
    }
    string name = scan_name;
    Vector!ubyte substring;
    Vector!string elems;
    size_t level = 0;
    
    elems.pushBack(name[0 .. name.find('(')]);
    name = name[name.find('(') .. $];
    
    foreach(size_t pos, const char c; name)
    {
        
        if (c == '(')
            ++level;
        if (c == ')')
        {
            if (level == 1 && pos == (name.length - 1))
            {
                if (elems.length == 1)
                    elems.pushBack(substring[1 .. $]);
                else
                    elems.pushBack(substring[]);
                return elems;
            }
            
            if (level == 0 || (level == 1 && pos != (name.length - 1)))
                throw new InvalidAlgorithmName(scan_name);
            --level;
        }
        
        if (c == ',' && level == 1)
        {
            if (elems.length == 1)
                elems.pushBack(substring[1 .. $]);
            else
                elems.pushBack(substring[]);
            substring.clear();
        }
        else
            substring ~= c;
    }
    
    if (substring.length > 0)
        throw new InvalidAlgorithmName(scan_name);
    
    return elems;
}

/**
* Split a string
* @param str = the input string
* @param delim = the delimitor
* @return string split by delim
*/
Vector!string splitter(in string str, char delim)
{
    return splitOnPred(str, (char c) { return c == delim; });
}

/**
* Split a string on a character predicate
* @param str = the input string
*/
Vector!string splitOnPred(in string str,
                            bool delegate(char) pred)
{
    Vector!string elems;
    if (str == "") return elems;
    import std.array : Appender;
    Vector!ubyte substr;
    foreach(const char c; str)
    {
        if (pred(c))
        {
            if (substr.length > 0)
                elems.pushBack(substr[]);
            substr.clear();
        }
        else
            substr ~= c;
    }
    
    if (substr.length > 0)
        throw new InvalidArgument("Unable to split string: " ~ str);
    elems.pushBack(substr[]);
    
    return elems;
}

/**
* Erase characters from a string
*/
string eraseChars(in string str, in char[] chars)
{
    import std.algorithm : canFind;
    import std.array : Appender;
    Appender!string output;
    
    foreach(const char c; str)
        if (!chars.canFind(c))
            output ~= c;
    
    return output.data;
}

/**
* Replace a character in a string
* @param str = the input string
* @param from_char = the character to replace
* @param to_char = the character to replace it with
* @return str with all instances of from_char replaced by to_char
*/
string replaceChar(in string str, in char from_char, in char to_char)
{   
    char[] output = str.dup;
    foreach (ref char c; output)
        if (c == from_char)
            c = to_char;
    
    return cast(string)output;
}

/**
* Replace a character in a string
* @param str = the input string
* @param from_chars = the characters to replace
* @param to_char = the character to replace it with
* @return str with all instances of from_chars replaced by to_char
*/

string replaceChars(in string str,
                    in char[] chars,
                    in char to_char)
{
    import std.algorithm : canFind;
    char[] output = str.dup;
    foreach (ref char c; output)
        if (chars.canFind(c))
            c = to_char;
    
    return cast(string)output;
}

/**
* Join a string
* @param strs = strings to join
* @param delim = the delimitor
* @return string joined by delim
*/
string stringJoin(in Vector!string strs, char delim)
{
    import std.algorithm : joiner;
    import std.array : array;
    return strs[].array.joiner(delim.to!string).to!string;
}

/**
* Parse an ASN.1 OID
* @param oid = the OID in string form
* @return OID components
*/
Vector!uint parseAsn1Oid(in string oid)
{
    import std.array : Appender, array;
    Vector!ubyte substring;
    Vector!uint oid_elems;
    

    foreach (char c; oid)
    {
        if (c == '.')
        {
            if (substring.length == 0)
                throw new InvalidOID(oid);
            oid_elems ~= to!uint(substring[]);
            substring.clear();
        }
        else {
            substring ~= c;
        }
    }
    
    if (substring.length == 0)
        throw new InvalidOID(oid);
    oid_elems ~= to!uint(substring[]);    
    substring.clear();

    if (oid_elems.length < 2)
        throw new InvalidOID(oid);
    return oid_elems;
}

/**
* Compare two names using the X.509 comparison algorithm
* @param name1 = the first name
* @param name2 = the second name
* @return true if name1 is the same as name2 by the X.509 comparison rules
*/
bool x500NameCmp(in string name1, in string name2)
{
    auto p1 = name1.ptr;
    auto p2 = name2.ptr;
    
    while ((p1 != name1.ptr + name1.length) && isSpace(*p1)) ++p1;
    while ((p2 != name2.ptr + name2.length) && isSpace(*p2)) ++p2;
    
    while (p1 != name1.ptr + name1.length && p2 != name2.ptr + name2.length)
    {
        if (isSpace(*p1))
        {
            if (!isSpace(*p2))
                return false;
            
            while ((p1 != name1.ptr + name1.length) && isSpace(*p1)) ++p1;
            while ((p2 != name2.ptr + name2.length) && isSpace(*p2)) ++p2;
            
            if (p1 == name1.ptr + name1.length && p2 == name2.ptr + name2.length)
                return true;
        }
        
        if (!caselessCmp(*p1, *p2))
            return false;
        ++p1;
        ++p2;
    }
    
    while ((p1 != name1.ptr + name1.length) && isSpace(*p1)) ++p1;
    while ((p2 != name2.ptr + name2.length) && isSpace(*p2)) ++p2;
    
    if ((p1 != name1.ptr + name1.length) || (p2 != name2.ptr + name2.length))
        return false;
    return true;
}

/**
* Convert a string representation of an IPv4 address to a number
* @param ip_str = the string representation
* @return integer IPv4 address
*/
uint stringToIpv4(in string str)
{
    Vector!string parts = splitter(str, '.');
    
    if (parts.length != 4)
        throw new DecodingError("Invalid IP string " ~ str);
    
    uint ip = 0;
    
    foreach (const string part; parts[])
    {
        uint octet = to!uint(part);
        
        if (octet > 255)
            throw new DecodingError("Invalid IP string " ~ str);
        
        ip = (ip << 8) | (octet & 0xFF);
    }
    
    return ip;
}

/**
* Convert an IPv4 address to a string
* @param ip_addr = the IPv4 address to convert
* @return string representation of the IPv4 address
*/
string ipv4ToString(uint ip)
{
    import std.array : Appender;
    Appender!string str;
    for (size_t i = 0; i != (ip).sizeof; ++i)
    {
        if (i)
            str ~= ".";
        str ~= to!string(get_byte(i, ip));
    }
    
    return str.data;
}

private:

ptrdiff_t find(string str, char c) {
    import std.algorithm : countUntil;
    return countUntil(str, c);
}

auto end(string str) {
    return str.ptr + str.length;
}
