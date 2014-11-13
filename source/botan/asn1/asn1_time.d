/*
* ASN.1 Time Representation
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.asn1_time;

import std.datetime;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.charset;
import botan.utils.parsing;
import botan.calendar;
import botan.utils.types;
import std.conv : to;
import std.array : Appender;

alias X509_Time = FreeListRef!X509_Time_Impl;

/**
* X.509 Time
*/
final class X509_Time_Impl : ASN1_Object
{
public:

	/*
	* DER encode a X509_Time
	*/
	void encode_into(DER_Encoder der) const
	{
		if (m_tag != ASN1_Tag.GENERALIZED_TIME && m_tag != ASN1_Tag.UTC_TIME)
			throw new Invalid_Argument("X509_Time: Bad encoding m_tag");
		
		der.add_object(m_tag, ASN1_Tag.UNIVERSAL,
		               transcode(toString(),
		                  LOCAL_CHARSET,
		                  LATIN1_CHARSET));
	}

	/*
	* Decode a BER encoded X509_Time
	*/
	void decode_from(BER_Decoder source)
	{
		BER_Object ber_time = source.get_next_object();
		
		set_to(transcode(asn1.toString(ber_time),
		                         LATIN1_CHARSET,
		                         LOCAL_CHARSET),
		       ber_time.type_tag);
	}

	/*
	* Return a string representation of the time
	*/
	string toString() const
	{
		if (time_is_set() == false)
			throw new Invalid_State("toString: No time set");
		
		uint full_year = m_year;
		
		if (m_tag == ASN1_Tag.UTC_TIME)
		{
			if (m_year < 1950 || m_year >= 2050)
				throw new Encoding_Error("X509_Time: The time " ~ readable_string() ~ " cannot be encoded as a UTCTime");
			
			full_year = (m_year >= 2000) ? (m_year - 2000) : (m_year - 1900);
		}
		
		string repr = to!string(full_year*10000000000 +
	                            m_month*100000000 +
	                            m_day*1000000 +
	                            m_hour*10000 +
	                            m_minute*100 +
	                            m_second) ~ "Z";
		
		uint desired_size = (m_tag == ASN1_Tag.UTC_TIME) ? 13 : 15;
		
		while(repr.length < desired_size)
			repr = "0" ~ repr;
		
		return repr;
	}

	/*
	* Return a human readable string representation
	*/
	string readable_string() const
	{
		if (time_is_set() == false)
			throw new Invalid_State("readable_string: No time set");
		import std.string : format;
		
		return format("%04d/%02d/%02d %02d:%02d:%02d UTC",
							m_year, m_month, m_day, m_hour, m_minute, m_second);
	}

	/*
	* Return if the time has been set somehow
	*/
	bool time_is_set() const
	{
		return (m_year != 0);
	}


	string toString() const { return readable_string(); }


	/*
	* Compare this time against another
	*/
	int cmp(in X509_Time other) const
	{
		if (time_is_set() == false)
			throw new Invalid_State("cmp: No time set");
		
		const int EARLIER = -1, LATER = 1, SAME_TIME = 0;
		
		if (m_year < other.m_year)	  return EARLIER;
		if (m_year > other.m_year)	  return LATER;
		if (m_month < other.m_month)	return EARLIER;
		if (m_month > other.m_month)	return LATER;
		if (m_day < other.m_day)		 return EARLIER;
		if (m_day > other.m_day)		 return LATER;
		if (m_hour < other.m_hour)	  return EARLIER;
		if (m_hour > other.m_hour)	  return LATER;
		if (m_minute < other.m_minute) return EARLIER;
		if (m_minute > other.m_minute) return LATER;
		if (m_second < other.m_second) return EARLIER;
		if (m_second > other.m_second) return LATER;
		
		return SAME_TIME;
	}

	/*
	* Set the time with a human readable string
	*/
	void set_to(in string time_str)
	{
		if (time_str == "")
		{
			m_year = m_month = m_day = m_hour = m_minute = m_second = 0;
			m_tag = ASN1_Tag.NO_OBJECT;
			return;
		}
		
		Vector!string params;
		Appender!string current;
		
		for (size_t j = 0; j != time_str.length; ++j)
		{
			if (is_digit(time_str[j]))
				current ~= time_str[j];
			else
			{
				if (current.data != "")
					params.push_back(current.data);
				current.clear();
			}
		}
		if (current.data != "")
			params.push_back(current.data);
		
		if (params.length < 3 || params.length > 6)
			throw new Invalid_Argument("Invalid time specification " ~ time_str);
		
		m_year	= to!uint(params[0]);
		m_month  = to!uint(params[1]);
		m_day	 = to!uint(params[2]);
		m_hour	= (params.length >= 4) ? to!uint(params[3]) : 0;
		m_minute = (params.length >= 5) ? to!uint(params[4]) : 0;
		m_second = (params.length == 6) ? to!uint(params[5]) : 0;
		
		m_tag = (m_year >= 2050) ? ASN1_Tag.GENERALIZED_TIME : ASN1_Tag.UTC_TIME;
		
		if (!passes_sanity_check())
			throw new Invalid_Argument("Invalid time specification " ~ time_str);
	}


	/*
	* Set the time with an ISO time format string
	*/
	void set_to(in string t_spec, ASN1_Tag spec_tag)
	{
		if (spec_tag == ASN1_Tag.GENERALIZED_TIME)
		{
			if (t_spec.length != 13 && t_spec.length != 15)
				throw new Invalid_Argument("Invalid GeneralizedTime: " ~ t_spec);
		}
		else if (spec_tag == ASN1_Tag.UTC_TIME)
		{
			if (t_spec.length != 11 && t_spec.length != 13)
				throw new Invalid_Argument("Invalid UTCTime: " ~ t_spec);
		}
		else
		{
			throw new Invalid_Argument("Invalid time m_tag " ~ to!string(spec_tag) ~ " val " ~ t_spec);
		}
		
		if (t_spec[t_spec.length-1] != 'Z')
			throw new Invalid_Argument("Invalid time encoding: " ~ t_spec);
		
		const size_t YEAR_SIZE = (spec_tag == ASN1_Tag.UTC_TIME) ? 2 : 4;
		
		Vector!string params;
		Appender!string current;
		current.reserve(YEAR_SIZE);
		foreach (size_t j; 0 .. YEAR_SIZE)
			current ~= t_spec[j];
		params.push_back(current.data);
		current.clear();
		
		for (size_t j = YEAR_SIZE; j != t_spec.length - 1; ++j)
		{
			current ~= t_spec[j];
			if (current.length == 2)
			{
				params.push_back(current);
				current.clear();
			}
		}
		
		m_year	= to!uint(params[0]);
		m_month  = to!uint(params[1]);
		m_day	 = to!uint(params[2]);
		m_hour	= to!uint(params[3]);
		m_minute = to!uint(params[4]);
		m_second = (params.length == 6) ? to!uint(params[5]) : 0;
		m_tag	 = spec_tag;
		
		if (spec_tag == ASN1_Tag.UTC_TIME)
		{
			if (m_year >= 50) m_year += 1900;
			else			  m_year += 2000;
		}
		
		if (!passes_sanity_check())
			throw new Invalid_Argument("Invalid time specification " ~ t_spec);
	}

	/*
	* Create a X509_Time from a time point
	*/
	this(in SysTime time)
	{
		m_year	= time.year;
		m_month  = time.month;
		m_day	 = time.day;
		m_hour	= time.hour;
		m_minute = time.minute;
		m_second = time.second;
		
		m_tag = (m_year >= 2050) ? ASN1_Tag.GENERALIZED_TIME : ASN1_Tag.UTC_TIME;
	}
	
	/*
	* Create an X509_Time
	*/
	this(in string t_spec, ASN1_Tag t)
	{
		m_tag = t;
		set_to(t_spec, m_tag);
	}

	/*
	* Create an X509_Time
	*/
	this(in string time_str)
	{
		set_to(time_str);
	}

	/*
	* Compare two X509_Times for in various ways
	*/
	bool opEquals(const X509_Time t2)
	{ return (cmp(t2) == 0); }

	bool opCmp(string op)(const X509_Time t2)
		if (op == "!=")
	{ return (t1.cmp(t2) != 0); }
	
	bool opCmp(string op)(const X509_Time t2)
		if (op == "<=")
	{ return (t1.cmp(t2) <= 0); }

	bool opCmp(string op)(const X509_Time t2)
		if (op == ">=")
	{ return (t1.cmp(t2) >= 0); }
	
	bool opCmp(string op)(const X509_Time t2)
		if (op == "<")
	{ return (t1.cmp(t2) < 0); }

	bool opCmp(string op)(const X509_Time t2)
		if (op == ">")
	{ return (t1.cmp(t2) > 0); }


private:
	/*
	* Do a general sanity check on the time
	*/
	bool passes_sanity_check() const
	{
		if (m_year < 1950 || m_year > 2100)
			return false;
		if (m_month == 0 || m_month > 12)
			return false;
		if (m_day == 0 || m_day > 31)
			return false;
		if (m_hour >= 24 || m_minute > 60 || m_second > 60)
			return false;
		return true;
	}

	uint m_year, m_month, m_day, m_hour, m_minute, m_second;
	ASN1_Tag m_tag;
}