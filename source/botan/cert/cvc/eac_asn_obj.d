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
import botan.parsing;
import std.datetime;

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
		der.add_object(tag, ASN1_Tag.APPLICATION,
		               encoded_eac_time());
	}

	/*
	* Decode a BER encoded EAC_Time
	*/
	void decode_from(BER_Decoder source = BER_Decoder())
	{
		BER_Object obj = source.get_next_object();
		
		if (obj.type_tag != this.tag)
			throw new BER_Decoding_Error("Tag mismatch when decoding");
		
		if (obj.value.size() != 6)
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
	string as_string() const
	{
		if (time_is_set() == false)
			throw new Invalid_State("as_string: No time set");
		
		return std.conv.to!string(year * 10000 + month * 100 + day);
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
		string current;
		
		for (uint j = 0; j != time_str.size(); ++j)
		{
			if (Charset.is_digit(time_str[j]))
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
		
		if (params.size() != 3)
			throw new Invalid_Argument("Invalid time specification " ~ time_str);
		
		year	= to_uint(params[0]);
		month  = to_uint(params[1]);
		day	 = to_uint(params[2]);
		
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
		tag = t;
		calendar_point cal = calendar_value(time);
		
		year = cal.year;
		month = cal.month;
		day	= cal.day;
	}

	/*
	* Create an EAC_Time
	*/
	this(in string t_spec, ASN1_Tag t = ASN1_Tag(0))
	{
		tag = t;
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
		tag = t;
	}

	/*
* Compare two EAC_Times for in various ways
*/
	bool opEquals(const ref EAC_Time t2)
	{
		return (cmp(t2) == 0);
	}
	
	bool opCmp(string op)(const ref EAC_Time t2)
		if (op == "!=")
	{
		return (cmp(t2) != 0);
	}

	bool opCmp(string op)(const ref EAC_Time t2)
		if (op == "<=")
	{
		return (cmp(t2) <= 0);
	}

	bool opCmp(string op)(const ref EAC_Time t2)
		if (op == ">=")
	{
		return (cmp(t2) >= 0);
	}

	bool opBinary(string op)(const ref EAC_Time t2)
		if (op == ">")
	{
		return (cmp(t2) > 0);
	}

	bool opBinary(string op)(const ref EAC_Time t2)
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
		Vector!ubyte result;
		result += enc_two_digit(year);
		result += enc_two_digit(month);
		result += enc_two_digit(day);
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
	ASN1_Tag tag;
};

/**
* This class represents CVC CEDs. Only limited sanity checks of
* the inputted date value are performed.
*/
class ASN1_Ced : EAC_Time
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
		super(other.get_year(), other.get_month(), other.get_day(),
		      ASN1_Tag(37));
	}
};

/**
* This class represents CVC CEXs. Only limited sanity checks of
* the inputted date value are performed.
*/
class ASN1_Cex : EAC_Time
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
};

/**
* Base class for car/chr of cv certificates.
*/
class ASN1_EAC_String : ASN1_Object
{
public:
	/*
	* DER encode an ASN1_EAC_String
	*/
	void encode_into(DER_Encoder encoder = DER_Encoder()) const
	{
		string value = iso_8859();
		encoder.add_object(tagging(), ASN1_Tag.APPLICATION, value);
	}
	
	/*
	* Decode a BER encoded ASN1_EAC_String
	*/
	void decode_from(BER_Decoder source = BER_Decoder())
	{
		BER_Object obj = source.get_next_object();
		
		if (obj.type_tag != this.tag)
		{
			import std.array : Appender;
			Appender!string ss;
			
			ss ~= "ASN1_EAC_String tag mismatch, tag was "
				 ~ obj.type_tag
					~ " expected "
					 ~ this.tag;
			
			throw new Decoding_Error(ss.data);
		}
		
		Character_Set charset_is;
		charset_is = LATIN1_CHARSET;
		
		try
		{
			*this = ASN1_EAC_String(
				Charset.transcode(asn1.to_string(obj), charset_is, LOCAL_CHARSET),
				obj.type_tag);
		}
		catch(Invalid_Argument inv_arg)
		{
			throw new Decoding_Error(string("ASN1_EAC_String decoding failed: ") +
			                         inv_arg.what());
		}
	}
	

	/**
	* Get this objects string value.
	* @return string value
	*/
	string value() const
	{
		return Charset.transcode(iso_8859_str, LATIN1_CHARSET, LOCAL_CHARSET);
	}

	/**
	* Get this objects string value.
	* @return string value in iso8859 encoding
	*/
	string iso_8859() const
	{
		return iso_8859_str;
	}

	/*
	* Return the type of this string object
	*/
	ASN1_Tag tagging() const
	{
		return tag;
	}

	/*
	* Create an ASN1_EAC_String
	*/
	this(in string str, ASN1_Tag t)
	{
		tag = t;
		iso_8859_str = Charset.transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
		
		if (!sanity_check())
			throw new Invalid_Argument("ASN1_EAC_String contains illegal characters");
	}

	bool opEquals(const ref ASN1_EAC_String rhs)
	{
		return (iso_8859() == rhs.iso_8859());
	}

	bool opCmp(string op)(const ref ASN1_EAC_String rhs)
		if (op == "!=")
	{
		return !(lhs == rhs);
	}

	~this() {}
package:
	// checks for compliance to the alphabet defined in TR-03110 v1.10, 2007-08-20
	// p. 43
	bool sanity_check() const
	{
		const ubyte* rep = cast(const ubyte*)(iso_8859_str.data());
		const size_t rep_len = iso_8859_str.size();
		
		for (size_t i = 0; i != rep_len; ++i)
		{
			if ((rep[i] < 0x20) || ((rep[i] >= 0x7F) && (rep[i] < 0xA0)))
				return false;
		}
		
		return true;
	}

private:
	string iso_8859_str;
	ASN1_Tag tag;
};

/**
* This class represents CARs of CVCs. (String tagged with 2)
*/
class ASN1_Car : ASN1_EAC_String
{
public:
	/**
	* Create a CAR with the specified content.
	* @param str the CAR value
	*/
	this(const ref string str)
	{
		super(str, ASN1_Tag(2));

	}
		
};

/**
* This class represents CHRs of CVCs (tag 32)
*/
class ASN1_Chr : ASN1_EAC_String
{
public:
	/**
	* Create a CHR with the specified content.
	* @param str the CHR value
	*/
	this(const ref string str)
	{
		super(str, ASN1_Tag(32));
	}

};


Vector!ubyte enc_two_digit(uint input)
{
	Vector!ubyte result;
	input %= 100;
	if (input < 10)
		result.push_back(0x00);
	else
	{
		uint y_first_pos = round_down!uint(input, 10) / 10;
		result.push_back(cast(ubyte)(y_first_pos));
	}
	
	uint y_sec_pos = input % 10;
	result.push_back(cast(ubyte)(y_sec_pos));
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