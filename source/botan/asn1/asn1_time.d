/*
* X.509 Time Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.asn1_time;
import botan.der_enc;
import botan.ber_dec;
import botan.charset;
import botan.parsing;
import botan.calendar;
/*
* Create an X509_Time
*/
X509_Time::X509_Time(in string time_str)
{
	set_to(time_str);
}

/*
* Create a X509_Time from a time point
*/
X509_Time::X509_Time(in SysTime time)
{
	calendar_point cal = calendar_value(time);

	year	= cal.year;
	month  = cal.month;
	day	 = cal.day;
	hour	= cal.hour;
	minute = cal.minutes;
	second = cal.seconds;

	tag = (year >= 2050) ? GENERALIZED_TIME : UTC_TIME;
}

/*
* Create an X509_Time
*/
X509_Time::X509_Time(in string t_spec, ASN1_Tag t) : tag(t)
{
	set_to(t_spec, tag);
}

/*
* Set the time with a human readable string
*/
void X509_Time::set_to(in string time_str)
{
	if (time_str == "")
	{
		year = month = day = hour = minute = second = 0;
		tag = NO_OBJECT;
		return;
	}

	Vector!string params;
	string current;

	for (size_t j = 0; j != time_str.size(); ++j)
	{
		if (Charset::is_digit(time_str[j]))
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

	if (params.size() < 3 || params.size() > 6)
		throw new Invalid_Argument("Invalid time specification " + time_str);

	year	= to_uint(params[0]);
	month  = to_uint(params[1]);
	day	 = to_uint(params[2]);
	hour	= (params.size() >= 4) ? to_uint(params[3]) : 0;
	minute = (params.size() >= 5) ? to_uint(params[4]) : 0;
	second = (params.size() == 6) ? to_uint(params[5]) : 0;

	tag = (year >= 2050) ? GENERALIZED_TIME : UTC_TIME;

	if (!passes_sanity_check())
		throw new Invalid_Argument("Invalid time specification " + time_str);
}

/*
* Set the time with an ISO time format string
*/
void X509_Time::set_to(in string t_spec, ASN1_Tag spec_tag)
{
	if (spec_tag == GENERALIZED_TIME)
	{
		if (t_spec.size() != 13 && t_spec.size() != 15)
			throw new Invalid_Argument("Invalid GeneralizedTime: " + t_spec);
	}
	else if (spec_tag == UTC_TIME)
	{
		if (t_spec.size() != 11 && t_spec.size() != 13)
			throw new Invalid_Argument("Invalid UTCTime: " + t_spec);
	}
	else
	{
		throw new Invalid_Argument("Invalid time tag " + std::to_string(spec_tag) + " val " + t_spec);
	}

	if (t_spec[t_spec.size()-1] != 'Z')
		throw new Invalid_Argument("Invalid time encoding: " + t_spec);

	const size_t YEAR_SIZE = (spec_tag == UTC_TIME) ? 2 : 4;

	Vector!string params;
	string current;

	for (size_t j = 0; j != YEAR_SIZE; ++j)
		current += t_spec[j];
	params.push_back(current);
	current.clear();

	for (size_t j = YEAR_SIZE; j != t_spec.size() - 1; ++j)
	{
		current += t_spec[j];
		if (current.size() == 2)
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
	second = (params.size() == 6) ? to_uint(params[5]) : 0;
	tag	 = spec_tag;

	if (spec_tag == UTC_TIME)
	{
		if (year >= 50) year += 1900;
		else			  year += 2000;
	}

	if (!passes_sanity_check())
		throw new Invalid_Argument("Invalid time specification " + t_spec);
}

/*
* DER encode a X509_Time
*/
void X509_Time::encode_into(DER_Encoder der) const
{
	if (tag != GENERALIZED_TIME && tag != UTC_TIME)
		throw new Invalid_Argument("X509_Time: Bad encoding tag");

	der.add_object(tag, UNIVERSAL,
						Charset::transcode(as_string(),
												 LOCAL_CHARSET,
												 LATIN1_CHARSET));
}

/*
* Decode a BER encoded X509_Time
*/
void X509_Time::decode_from(BER_Decoder source)
{
	BER_Object ber_time = source.get_next_object();

	set_to(Charset::transcode(ASN1::to_string(ber_time),
									  LATIN1_CHARSET,
									  LOCAL_CHARSET),
			 ber_time.type_tag);
}

/*
* Return a string representation of the time
*/
string X509_Time::as_string() const
{
	if (time_is_set() == false)
		throw new Invalid_State("X509_Time::as_string: No time set");

	uint full_year = year;

	if (tag == UTC_TIME)
	{
		if (year < 1950 || year >= 2050)
			throw new Encoding_Error("X509_Time: The time " + readable_string() +
										" cannot be encoded as a UTCTime");

		full_year = (year >= 2000) ? (year - 2000) : (year - 1900);
	}

	string repr = std::to_string(full_year*10000000000 +
												 month*100000000 +
												 day*1000000 +
												 hour*10000 +
												 minute*100 +
												 second) + "Z";

	uint desired_size = (tag == UTC_TIME) ? 13 : 15;

	while(repr.size() < desired_size)
		repr = "0" + repr;

	return repr;
}

/*
* Return if the time has been set somehow
*/
bool X509_Time::time_is_set() const
{
	return (year != 0);
}

/*
* Return a human readable string representation
*/
string X509_Time::readable_string() const
{
	if (time_is_set() == false)
		throw new Invalid_State("X509_Time::readable_string: No time set");

	string output(24, 0);

	std::sprintf(&output[0], "%04d/%02d/%02d %02d:%02d:%02d UTC",
					 year, month, day, hour, minute, second);

	output.resize(23); // remove trailing null

	return output;
}

/*
* Do a general sanity check on the time
*/
bool X509_Time::passes_sanity_check() const
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

/*
* Compare this time against another
*/
s32bit X509_Time::cmp(in X509_Time other) const
{
	if (time_is_set() == false)
		throw new Invalid_State("X509_Time::cmp: No time set");

	const s32bit EARLIER = -1, LATER = 1, SAME_TIME = 0;

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
* Compare two X509_Times for in various ways
*/
bool operator==(in X509_Time t1, const X509_Time& t2)
{ return (t1.cmp(t2) == 0); }
bool operator!=(in X509_Time t1, const X509_Time& t2)
{ return (t1.cmp(t2) != 0); }

bool operator<=(in X509_Time t1, const X509_Time& t2)
{ return (t1.cmp(t2) <= 0); }
bool operator>=(in X509_Time t1, const X509_Time& t2)
{ return (t1.cmp(t2) >= 0); }

bool operator<(in X509_Time t1, const X509_Time& t2)
{ return (t1.cmp(t2) < 0); }
bool operator>(in X509_Time t1, const X509_Time& t2)
{ return (t1.cmp(t2) > 0); }

}
