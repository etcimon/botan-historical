/*
* SCAN Name Abstraction
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/
module botan.algo_base.scan_name;

import botan.utils.parsing;
import botan.utils.exceptn;
import std.exception;
import std.array : Appender;
import botan.utils.types;
// import string;
import std.conv : to;
import core.sync.mutex;
import botan.utils.containers.hashmap;

/**
A class encapsulating a SCAN name (similar to JCE conventions)
http://www.users.zetnet.co.uk/hopwood/crypto/scan/
*/
struct SCANName
{
public:
    /**
    * @param algo_spec = A SCAN-format name
    */
    this(string algo_spec)
    {
        m_orig_algo_spec = algo_spec;
        
        Vector!( Pair!(size_t, string)  ) names;
        size_t level = 0;
        Appender!string def_buf;
        def_buf.reserve(8);
        Pair!(size_t, Appender!string) accum = Pair(level, def_buf);
        
        string decoding_error = "Bad SCAN name '" ~ algo_spec ~ "': ";
        
        algo_spec = derefAlias(algo_spec);
        
        foreach (immutable(char) c; algo_spec)
        {

            if (c == '/' || c == ',' || c == '(' || c == ')')
            {
                if (c == '(')
                    ++level;
                else if (c == ')')
                {
                    if (level == 0)
                        throw new DecodingError(decoding_error ~ "Mismatched parens");
                    --level;
                }
                
                if (c == '/' && level > 0)
                    accum.second ~= c;
                else
                {
                    if (accum.second.length > 0)
                        names.pushBack(derefAliases(Pair(accum.first, accum.second.data)));
                    Appender!string str;
                    str.reserve(8);
                    accum = Pair(level, str);
                }
            }
            else
                accum.second ~= c;
        }
        
        if (accum.second.length > 0)
            names.pushBack(derefAliases(Pair(accum.first, accum.second.data)));
        
        if (level != 0)
            throw new DecodingError(decoding_error ~ "Missing close paren");
        
        if (names.length == 0)
            throw new DecodingError(decoding_error ~ "Empty name");
        
        m_alg_name = names[0].second;
        
        bool in_modes;

        foreach (const name; names[])
        {
            if (name.first == 0)
            {
                m_mode_info.pushBack(makeArg(names, i));
                in_modes = true;
            }
            else if (name.first == 1 && !in_modes)
                m_args.pushBack(makeArg(names, i));
        }
    }
    
    /**
    * @return original input string
    */
    string toString() const { return m_orig_algo_spec; }
    
    /**
    * @return algorithm name
    */
    @property string algoName() const { return m_alg_name; }
    
    /**
    * @return algorithm name plus any arguments
    */
    string algoNameAndArgs() const
    {
        Appender!string output;
        
        output = algo_name;
        
        if (argCount())
        {
            output ~= '(';
            foreach (size_t i; 0 .. argCount())
            {
                output ~= arg(i);
                if (i != argCount() - 1)
                    output ~= ',';
            }
            output ~= ')';
            
        }
        
        return output.data;
    }
    
    /**
    * @return number of arguments
    */
    size_t argCount() const { return m_args.length; }
    
    /**
    * @param lower = is the lower bound
    * @param upper = is the upper bound
    * @return if the number of arguments is between lower and upper
    */
    bool argCountBetween(size_t lower, size_t upper) const
    { return ((argCount() >= lower) && (argCount() <= upper)); }
    
    /**
    * @param i = which argument
    * @return ith argument
    */
    string arg(size_t i) const
    {
        if (i >= argCount())
            throw new RangeError("SCANName.argument - i out of range");
        return m_args[i];
    }
    
    /**
    * @param i = which argument
    * @param def_value = the default value
    * @return ith argument or the default value
    */
    string arg(size_t i, in string def_value) const
    {
        if (i >= argCount())
            return def_value;
        return m_args[i];
    }
    
    /**
    * @param i = which argument
    * @param def_value = the default value
    * @return ith argument as an integer, or the default value
    */
    size_t argAsInteger(size_t i, size_t def_value) const
    {
        if (i >= argCount())
            return def_value;
        return to!uint(m_args[i]);
    }
    
    /**
    * @return cipher mode (if any)
    */
    string cipherMode() const
    { return (m_mode_info.length >= 1) ? m_mode_info[0] : ""; }
    
    /**
    * @return cipher mode padding (if any)
    */
    string cipherModePad() const
    { return (m_mode_info.length >= 2) ? m_mode_info[1] : ""; }
    
    static void addAlias(in string _alias, in string basename)
    {
        
        if (s_alias_map.get(_alias, null) is null)
            s_alias_map[_alias] = basename;
    }

    
    static string derefAliases(in Pair!(size_t, string) input)
    {
        return Pair(input.first, s_alias_map.get(input.second));
    }

    static void setDefaultAliases()
    {
        // common variations worth supporting
        addAlias("EME-PKCS1-v1_5",    "PKCS1v15");
        addAlias("3DES",            "TripleDES");
        addAlias("DES-EDE",        "TripleDES");
        addAlias("CAST5",            "CAST-128");
        addAlias("SHA1",            "SHA-160");
        addAlias("SHA-1",            "SHA-160");
        addAlias("MARK-4",            "RC4(256)");
        addAlias("ARC4",              "RC4");
        addAlias("OMAC",              "CMAC");
            
        addAlias("EMSA-PSS",        "PSSR");
        addAlias("PSS-MGF1",        "PSSR");
        addAlias("EME-OAEP",        "OAEP");
            
        addAlias("EMSA2",            "EMSA_X931");
        addAlias("EMSA3",            "EMSA_PKCS1");
        addAlias("EMSA-PKCS1-v1_5","EMSA_PKCS1");
            
            // should be renamed in sources
        addAlias("X9.31",            "EMSA2");
            
            // kept for compatability with old library versions
        addAlias("EMSA4",            "PSSR");
        addAlias("EME1",            "OAEP");
            
            // probably can be removed
        addAlias("GOST",            "GOST-28147-89");
        addAlias("GOST-34.11",        "GOST-R-34.11-94");
    }
    

private:
    static HashMap!(string, string) s_alias_map;
    
    string m_orig_algo_spec;
    string m_alg_name;
    Vector!string m_args;
    Vector!string m_mode_info;
}

string makeArg(in Vector!(Pair!(size_t, string)) names, size_t start)
{
    Appender!string output;
    output ~= name[start].second;
    size_t level = name[start].first;
    
    size_t paren_depth = 0;
    
    foreach (name; name[start + 1 .. $])
    {
        if (name.first <= name[start].first)
            break;
        
        if (name.first > level)
        {
            output ~= '(' + name.second;
            ++paren_depth;
        }
        else if (name.first < level)
        {
            output ~= ")," ~ name.second;
            --paren_depth;
        }
        else
        {
            if (output[output.length - 1] != '(')
                output ~= ",";
            output ~= name.second;
        }
        
        level = name.first;
    }
    
    foreach (i; 0 .. paren_depth)
        output ~= ')';
    
    return output.data;
}


string makeArg(
    const Vector!(Pair!(size_t, string)) names, size_t start)
{
    Appender!string output;
    output ~= names[start].second;
    size_t level = names[start].first;

    size_t paren_depth = 0;

    foreach (name; names[(start + 1) .. $])
    {
        if (name.first <= name[start].first)
            break;

        if (name.first > level)
        {
            output ~= '(' + name.second;
            ++paren_depth;
        }
        else if (name.first < level)
        {
            output ~= ")," ~ name.second;
            --paren_depth;
        }
        else
        {
            if (output[output.length - 1] != '(')
                output ~= ",";
            output ~= name.second;
        }

        level = name.first;
    }

    foreach (size_t i; 0 .. paren_depth)
        output ~= ')';

    return output.data;
}