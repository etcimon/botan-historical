/*
* EAC ASN.1 Objects
* (C) 2007-2008 FlexSecure GmbH
*	  2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.eac_asn_obj;

import botan.asn1.asn1_obj;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.rounding;
import botan.calendar;
import botan.utils.charset;
import botan.utils.parsing;
import std.datetime;
import botan.utils.types;
import std.array : Appender;

alias ASN1_Car = FreeListRef!ASN1_Car_Impl;
alias ASN1_Chr = FreeListRef!ASN1_Chr_Impl;
alias ASN1_Cex = FreeListRef!ASN1_Cex_Impl;
alias ASN1_Ced = FreeListRef!ASN1_Ced_Impl;

/**
* This class represents CVC EAC Time objects.
* It only models year, month and day. Only limited sanity checks of
* the inputted date value are performed.
*/
class EAC_Time : ASN1_Object
{
public:

	/*
	* DER encode a EAC_Time
	*/
	void encode_into(DER_Encoder der) const
	{
		der.add_object(m_tag, ASN1_Tag.APPLICATION,
		               encoded_eac_time());
	}

	/*
	* Decode a BER encoded EAC_Time
	*/
	void decode_from(BER_Decoder source)
	{
		BER_Object obj = source.get_next_object();
		
		if (obj.type_tag != this.m_tag)
			throw new BER_Decoding_Error("Tag mismatch when decoding");
		
		if (obj.value.length != 6)
		{
			throw new Decoding_Error("EAC_Time decoding failed");
		}
		
		try
		{
			uint tmp_year = dec_two_digit(obj.value[0], obj.value[1]);
			uint tmp_mon = dec_two_digit(obj.value[2], obj.value[3]);
			uint tmp_day = dec_two_digit(obj.value[4], obj.value[5]);
			year = tmp_year + 2000;
			month = tmp_mon;
			day = tmp_day;
		}
		catch (Invalid_Argument)
		{
			throw new Decoding_Error("EAC_Time decoding failed");
		}
		
	}

	/**
	* Return a string representation of the time
	* @return date string
	*/
	string toString() const
	{
		if (time_is_set() == false)
			throw new Invalid_State("toString: No time set");
		
		return to!string(year * 10000 + month * 100 + day);
	}


	/**
	* Get a this objects value as a readable formatted string.
	* @return date string
	*/
	string readable_string() const
	{
		if (time_is_set() == false)
			throw new Invalid_State("readable_string: No time set");
		
		import std.string : format;
		return format("%04d/%02d/%02d", year, month, day);
	}

	/**
	* Find out whether this object's values have been set.
	* @return true if this object's internal values are set
	*/
	bool time_is_set() const
	{
		return (year != 0);
	}

	/**
	* Compare this to another EAC_Time object.
	* @return -1 if this object's date is earlier than
	* other, +1 in the opposite case, and 0 if both dates are
	* equal.
	*/
	int cmp(in EAC_Time other) const
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
		
		return SAME_TIME;
	}


	/**
	* Set this' value by a human readable string
	* @param str a string in the format "yyyy mm dd",
	* e.g. "2007 08 01"
	*/
	void set_to(in string time_str)
	{
		if (time_str == "")
		{
			year = month = day = 0;
			return;
		}
		
		Vector!string params;
		Appender!string current;
		current.reserve(time_str.length);
		
		for (uint j = 0; j != time_str.length; ++j)
		{
			if (is_digit(time_str[j]))
				current ~= time_str[j];
			else
			{
				if (current.data.length > 0)
					params.push_back(current.data);
				current.clear();
			}
		}
		if (current.data.length > 0)
			params.push_back(current.data);
		
		if (params.length != 3)
			throw new Invalid_Argument("Invalid time specification " ~ time_str);
		
		year	= to!uint(params[0]);
		month  = to!uint(params[1]);
		day	 = to!uint(params[2]);
		
		if (!passes_sanity_check())
			throw new Invalid_Argument("Invalid time specification " ~ time_str);
	}

	/**
	* Add the specified number of years to this.
	* @param years the number of years to add
	*/
	void add_years(uint years)
	{
		year += years;
	}


	/**
	* Add the specified number of months to this.
	* @param months the number of months to add
	*/
	void add_months(uint months)
	{
		year += months/12;
		month += months % 12;
		if (month > 12)
		{
			year += 1;
			month -= 12;
		}
	}

	/**
	* Get the year value of this objects.
	* @return year value
	*/
	uint get_year() const { return year; }

	/**
	* Get the month value of this objects.
	* @return month value
	*/
	uint get_month() const { return month; }

	/**
	* Get the day value of this objects.
	* @return day value
	*/
	uint get_day() const { return day; }

	/*
	* Create an EAC_Time
	*/
	this(in SysTime time,
	         ASN1_Tag t = ASN1_Tag(0))
	{
		m_tag = t;
		
		year = time.year;
		month = time.month;
		day	= time.day;
	}

	/*
	* Create an EAC_Time
	*/
	this(in string t_spec, ASN1_Tag t = ASN1_Tag(0))
	{
		m_tag = t;
		set_to(t_spec);
	}

	/*
	* Create an EAC_Time
	*/
	this(uint y, uint m, uint d, ASN1_Tag t = ASN1_Tag(0))
	{
		year = y;
		month = m;
		day = d;
		m_tag = t;
	}

	/*
	* Compare two EAC_Times for in various ways
	*/
	bool opEquals(in EAC_Time t2)
	{
		return (cmp(t2) == 0);
	}
	
	bool opCmp(string op)(in EAC_Time t2)
		if (op == "!=")
	{
		return (cmp(t2) != 0);
	}

	bool opCmp(string op)(in EAC_Time t2)
		if (op == "<=")
	{
		return (cmp(t2) <= 0);
	}

	bool opCmp(string op)(in EAC_Time t2)
		if (op == ">=")
	{
		return (cmp(t2) >= 0);
	}

	bool opBinary(string op)(in EAC_Time t2)
		if (op == ">")
	{
		return (cmp(t2) > 0);
	}

	bool opBinary(string op)(in EAC_Time t2)
		if (op == "<")
	{
		return (cmp(t2) < 0);
	}

	~this() {}
private:
	/*
	* make the value an octet string for encoding
	*/
	Vector!ubyte encoded_eac_time() const
	{
		Vector!ubyte result = Vector!ubyte(6);
		result ~= enc_two_digit_arr(year);
		result ~= enc_two_digit_arr(month);
		result ~= enc_two_digit_arr(day);
		return result;
	}

	/*
	* Do a general sanity check on the time
	*/
	bool passes_sanity_check() const
	{
		if (year < 2000 || year > 2099)
			return false;
		if (month == 0 || month > 12)
			return false;
		if (day == 0 || day > 31)
			return false;
		
		return true;
	}
	uint year, month, day;
	ASN1_Tag m_tag;
}

/**
* This class represents CVC CEDs. Only limited sanity checks of
* the inputted date value are performed.
*/
final class ASN1_Ced_Impl : EAC_Time
{
public:
	/**
	* Construct a CED from a string value.
	* @param str a string in the format "yyyy mm dd",
	* e.g. "2007 08 01"
	*/
	this(in string str = "") {
		super(str, ASN1_Tag(37));
	}

	/**
	* Construct a CED from a time point
	*/
	this(in SysTime time) {
		super(time, ASN1_Tag(37));
	}

	/**
	* Copy constructor (for general EAC_Time objects).
	* @param other the object to copy from
	*/
	this(in EAC_Time other)
	{
		super(other.get_year(), other.get_month(), other.get_day(), ASN1_Tag(37));
	}
}

/**
* This class represents CVC CEXs. Only limited sanity checks of
* the inputted date value are performed.
*/
final class ASN1_Cex_Impl : EAC_Time
{
public:
	/**
	* Construct a CEX from a string value.
	* @param str a string in the format "yyyy mm dd",
	* e.g. "2007 08 01"
	*/
	this(in string str = "") 
	{
		super(str, ASN1_Tag(36));
	}

	this(in SysTime time)
	{
		super(time, ASN1_Tag(36));
	}

	this(in EAC_Time other)
	{
		super(other.get_year(), other.get_month(), other.get_day(),
		      ASN1_Tag(36));
	}
}

/**
* Base class for car/chr of cv certificates.
*/
class ASN1_EAC_String : ASN1_Object
{
public:
	/*
	* DER encode an ASN1_EAC_String
	*/
	void encode_into(DER_Encoder encoder) const
	{
		string value = iso_8859();
		encoder.add_object(tagging(), ASN1_Tag.APPLICATION, value);
	}
	
	/*
	* Decode a BER encoded ASN1_EAC_String
	*/
	void decode_from(BER_Decoder source)
	{
		BER_Object obj = source.get_next_object();
		
		if (obj.type_tag != this.m_tag)
		{
			Appender!string ss;
			
			ss ~= "ASN1_EAC_String tag mismatch, tag was "
				 ~ obj.type_tag
					~ " expected "
					 ~ this.m_tag;
			
			throw new Decoding_Error(ss.data);
		}
		
		Character_Set charset_is;
		charset_is = LATIN1_CHARSET;
		
		try
		{
			this = ASN1_EAC_String(transcode(obj.toString(),
			                                 charset_is, 
			                                 LOCAL_CHARSET),
			                       obj.type_tag);
		}
		catch(Invalid_Argument inv_arg)
		{
			throw new Decoding_Error(string("ASN1_EAC_String decoding failed: ") ~ inv_arg.msg);
		}
	}
	

	/**
	* Get this objects string value.
	* @return string value
	*/
	string value() const
	{
		return transcode(m_iso_8859_str, LATIN1_CHARSET, LOCAL_CHARSET);
	}

	/**
	* Get this objects string value.
	* @return string value in iso8859 encoding
	*/
	string iso_8859() const
	{
		return m_iso_8859_str;
	}

	/*
	* Return the type of this string object
	*/
	ASN1_Tag tagging() const
	{
		return m_tag;
	}

	/*
	* Create an ASN1_EAC_String
	*/
	this(in string str, ASN1_Tag t)
	{
		m_tag = t;
		m_iso_8859_str = transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
		
		if (!sanity_check())
			throw new Invalid_Argument("ASN1_EAC_String contains illegal characters");
	}

	bool opEquals(in ASN1_EAC_String rhs)
	{
		return (iso_8859() == rhs.iso_8859());
	}

	bool opCmp(string op)(in ASN1_EAC_String rhs)
		if (op == "!=")
	{
		return !(lhs == rhs);
	}

	~this() {}
protected:
	// checks for compliance to the alphabet defined in TR-03110 v1.10, 2007-08-20
	// p. 43
	bool sanity_check() const
	{
		const ubyte* rep = cast(const ubyte*) m_iso_8859_str.ptr;
		const size_t rep_len = m_iso_8859_str.length;
		
		foreach (size_t i; 0 .. rep_len)
		{
			if ((rep[i] < 0x20) || ((rep[i] >= 0x7F) && (rep[i] < 0xA0)))
				return false;
		}
		
		return true;
	}

private:
	string m_iso_8859_str;
	ASN1_Tag m_tag;
}

/**
* This class represents CARs of CVCs. (String tagged with 2)
*/
final class ASN1_Car_Impl : ASN1_EAC_String
{
public:
	/**
	* Create a CAR with the specified content.
	* @param str the CAR value
	*/
	this(in string str)
	{
		super(str, ASN1_Tag(2));

	}
		
}

/**
* This class represents CHRs of CVCs (tag 32)
*/
final class ASN1_Chr_Impl : ASN1_EAC_String
{
public:
	/**
	* Create a CHR with the specified content.
	* @param str the CHR value
	*/
	this(in string str)
	{
		super(str, ASN1_Tag(32));
	}

}


Vector!ubyte enc_two_digit(uint input)
{
	ubyte[2] res = enc_two_digit_arr(input);
	return Vector!ubyte(res.ptr[0 .. 2]);
}

ubyte[2] enc_two_digit_arr(uint input)
{
	ubyte[2] result;
	input %= 100;
	if (input < 10)
		result[0] = 0x00;
	else
	{
		uint y_first_pos = round_down!uint(input, 10) / 10;
		result[0] = cast(ubyte) y_first_pos;
	}
	
	uint y_sec_pos = input % 10;
	result[1] = cast(ubyte) y_sec_pos;
	return result;
}

uint dec_two_digit(ubyte b1, ubyte b2)
{
	uint upper = b1;
	uint lower = b2;
	
	if (upper > 9 || lower > 9)
		throw new Invalid_Argument("CVC dec_two_digit value too large");
	
	return upper*10 + lower;
}