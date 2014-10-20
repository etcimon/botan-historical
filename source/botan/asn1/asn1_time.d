/*
* ASN.1 Time Representation
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.asn1.asn1_time;

import std.datetime;
import botan.utils.mixins;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.charset;
import botan.utils.parsing;
import botan.calendar;

class DER_Encoder;
class BER_Decoder;

/**
* X.509 Time
*/
class X509_Time : ASN1_Object
{
public:
	import botan.utils.mixins;
	mixin USE_STRUCT_INIT!();
	/*
	* DER encode a X509_Time
	*/
	void encode_into(DER_Encoder der) const
	{
		if (tag != ASN1_Tag.GENERALIZED_TIME && tag != ASN1_Tag.UTC_TIME)
			throw new Invalid_Argument("X509_Time: Bad encoding tag");
		
		der.add_object(tag, ASN1_Tag.UNIVERSAL,
		               transcode(as_string(),
		                  LOCAL_CHARSET,
		                  LATIN1_CHARSET));
	}

	/*
	* Decode a BER encoded X509_Time
	*/
	void decode_from(BER_Decoder source = BER_Decoder())
	{
		BER_Object ber_time = source.get_next_object();
		
		set_to(transcode(asn1.to_string(ber_time),
		                         LATIN1_CHARSET,
		                         LOCAL_CHARSET),
		       ber_time.type_tag);
	}

	/*
	* Return a string representation of the time
	*/
	string as_string() const
	{
		if (time_is_set() == false)
			throw new Invalid_State("as_string: No time set");
		
		uint full_year = year;
		
		if (tag == ASN1_Tag.UTC_TIME)
		{
			if (year < 1950 || year >= 2050)
				throw new Encoding_Error("X509_Time: The time " ~ readable_string() +
				                         " cannot be encoded as a UTCTime");
			
			full_year = (year >= 2000) ? (year - 2000) : (year - 1900);
		}
		
		string repr = std.conv.to!string(full_year*10000000000 +
		                                 month*100000000 +
		                                 day*1000000 +
		                                 hour*10000 +
		                                 minute*100 +
		                                 second) ~ "Z";
		
		uint desired_size = (tag == ASN1_Tag.UTC_TIME) ? 13 : 15;
		
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
							year, month, day, hour, minute, second);
	}

	/*
	* Return if the time has been set somehow
	*/
	bool time_is_set() const
	{
		return (year != 0);
	}


	string to_string() const { return readable_string(); }


	/*
	* Compare this time against another
	*/
	int cmp(in X509_Time other) const
	{
		if (time_is_set() == false)
			throw new Invalid_State("cmp: No time set");
		
		const int EARLIER = -1, LATER = 1, SAME_TIME = 0;
		
		if (year < other.year)	  return EARLIER;
		if (year > other.year)	  return LATER;
		if (month < other.month)	return EARLIER;
		if (month > other.month)	return LATER;
		if (day < other.day)		 return EARLIER;
		if (day > other.day)		 return LATER;
		if (hour < other.hour)	  return EARLIER;
		if (hour > other.hour)	  return LATER;
		if (minute < other.minute) return EARLIER;
		if (minute > other.minute) return LATER;
		if (second < other.second) return EARLIER;
		if (second > other.second) return LATER;
		
		return SAME_TIME;
	}

	/*
	* Set the time with a human readable string
	*/
	void set_to(in string time_str)
	{
		if (time_str == "")
		{
			year = month = day = hour = minute = second = 0;
			tag = ASN1_Tag.NO_OBJECT;
			return;
		}
		
		Vector!string params;
		string current;
		
		for (size_t j = 0; j != time_str.length; ++j)
		{
			if (is_digit(time_str[j]))
				current += time_str[j];
			else
			{
				if (current != "")
					params.push_back(current);
				current.clear();
			}
		}
		if (current != "")
			params.push_back(current);
		
		if (params.length < 3 || params.length > 6)
			throw new Invalid_Argument("Invalid time specification " ~ time_str);
		
		year	= to_uint(params[0]);
		month  = to_uint(params[1]);
		day	 = to_uint(params[2]);
		hour	= (params.length >= 4) ? to_uint(params[3]) : 0;
		minute = (params.length >= 5) ? to_uint(params[4]) : 0;
		second = (params.length == 6) ? to_uint(params[5]) : 0;
		
		tag = (year >= 2050) ? ASN1_Tag.GENERALIZED_TIME : ASN1_Tag.UTC_TIME;
		
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
			throw new Invalid_Argument("Invalid time tag " ~ std.conv.to!string(spec_tag) ~ " val " ~ t_spec);
		}
		
		if (t_spec[t_spec.length-1] != 'Z')
			throw new Invalid_Argument("Invalid time encoding: " ~ t_spec);
		
		const size_t YEAR_SIZE = (spec_tag == ASN1_Tag.UTC_TIME) ? 2 : 4;
		
		Vector!string params;
		string current;
		
		for (size_t j = 0; j != YEAR_SIZE; ++j)
			current += t_spec[j];
		params.push_back(current);
		current.clear();
		
		for (size_t j = YEAR_SIZE; j != t_spec.length - 1; ++j)
		{
			current += t_spec[j];
			if (current.length == 2)
			{
				params.push_back(current);
				current.clear();
			}
		}
		
		year	= to_uint(params[0]);
		month  = to_uint(params[1]);
		day	 = to_uint(params[2]);
		hour	= to_uint(params[3]);
		minute = to_uint(params[4]);
		second = (params.length == 6) ? to_uint(params[5]) : 0;
		tag	 = spec_tag;
		
		if (spec_tag == ASN1_Tag.UTC_TIME)
		{
			if (year >= 50) year += 1900;
			else			  year += 2000;
		}
		
		if (!passes_sanity_check())
			throw new Invalid_Argument("Invalid time specification " ~ t_spec);
	}

	/*
	* Create a X509_Time from a time point
	*/
	this(in SysTime time)
	{
		calendar_point cal = calendar_value(time);
		
		year	= cal.year;
		month  = cal.month;
		day	 = cal.day;
		hour	= cal.hour;
		minute = cal.minutes;
		second = cal.seconds;
		
		tag = (year >= 2050) ? ASN1_Tag.GENERALIZED_TIME : ASN1_Tag.UTC_TIME;
	}
	
	/*
	* Create an X509_Time
	*/
	this(in string t_spec, ASN1_Tag t)
	{
		tag = t;
		set_to(t_spec, tag);
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
		if (year < 1950 || year > 2100)
			return false;
		if (month == 0 || month > 12)
			return false;
		if (day == 0 || day > 31)
			return false;
		if (hour >= 24 || minute > 60 || second > 60)
			return false;
		return true;
	}

	uint year, month, day, hour, minute, second;
	ASN1_Tag tag;
};