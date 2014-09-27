/*
* EAC ASN.1 Objects
* (C) 2007-2008 FlexSecure GmbH
*	  2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.asn1_obj;
import chrono;
/**
* This class represents CVC EAC Time objects.
* It only models year, month and day. Only limited sanity checks of
* the inputted date value are performed.
*/
class EAC_Time : public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder&) const;
		void decode_from(class BER_Decoder&);

		/**
		* Get a this objects value as a string.
		* @return date string
		*/
		string as_string() const;

		/**
		* Get a this objects value as a readable formatted string.
		* @return date string
		*/
		string readable_string() const;

		/**
		* Find out whether this object's values have been set.
		* @return true if this object's internal values are set
		*/
		bool time_is_set() const;

		/**
		* Compare this to another EAC_Time object.
		* @return -1 if this object's date is earlier than
		* other, +1 in the opposite case, and 0 if both dates are
		* equal.
		*/
		s32bit cmp(in EAC_Time other) const;

		/**
		* Set this' value by a string value.
		* @param str a string in the format "yyyy mm dd",
		* e.g. "2007 08 01"
		*/
		void set_to(in string str);

		/**
		* Add the specified number of years to this.
		* @param years the number of years to add
		*/
		void add_years(uint years);

		/**
		* Add the specified number of months to this.
		* @param months the number of months to add
		*/
		void add_months(uint months);

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

		EAC_Time(in SysTime time,
					ASN1_Tag tag = ASN1_Tag(0));

		EAC_Time(in string yyyy_mm_dd,
					ASN1_Tag tag = ASN1_Tag(0));

		EAC_Time(uint year, uint month, uint day,
					ASN1_Tag tag = ASN1_Tag(0));

		~this() {}
	private:
		Vector!( byte ) encoded_eac_time() const;
		bool passes_sanity_check() const;
		uint year, month, day;
		ASN1_Tag tag;
};

/**
* This class represents CVC CEDs. Only limited sanity checks of
* the inputted date value are performed.
*/
class ASN1_Ced : public EAC_Time
{
	public:
		/**
		* Construct a CED from a string value.
		* @param str a string in the format "yyyy mm dd",
		* e.g. "2007 08 01"
		*/
		ASN1_Ced(in string str = "") :
			EAC_Time(str, ASN1_Tag(37)) {}

		/**
		* Construct a CED from a time point
		*/
		ASN1_Ced(in SysTime time) :
			EAC_Time(time, ASN1_Tag(37)) {}

		/**
		* Copy constructor (for general EAC_Time objects).
		* @param other the object to copy from
		*/
		ASN1_Ced(in EAC_Time other) :
			EAC_Time(other.get_year(), other.get_month(), other.get_day(),
						ASN1_Tag(37))
		{}
};

/**
* This class represents CVC CEXs. Only limited sanity checks of
* the inputted date value are performed.
*/
class ASN1_Cex : public EAC_Time
{
	public:
		/**
		* Construct a CEX from a string value.
		* @param str a string in the format "yyyy mm dd",
		* e.g. "2007 08 01"
		*/
		ASN1_Cex(in string str = "") :
			EAC_Time(str, ASN1_Tag(36)) {}

		ASN1_Cex(in SysTime time) :
			EAC_Time(time, ASN1_Tag(36)) {}

		ASN1_Cex(in EAC_Time other) :
			EAC_Time(other.get_year(), other.get_month(), other.get_day(),
						ASN1_Tag(36))
		{}
};

/**
* Base class for car/chr of cv certificates.
*/
class ASN1_EAC_String: public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder&) const;
		void decode_from(class BER_Decoder&);

		/**
		* Get this objects string value.
		* @return string value
		*/
		string value() const;

		/**
		* Get this objects string value.
		* @return string value in iso8859 encoding
		*/
		string iso_8859() const;

		ASN1_Tag tagging() const;
		ASN1_EAC_String(in string str, ASN1_Tag the_tag);

		~this() {}
	protected:
		bool sanity_check() const;
	private:
		string iso_8859_str;
		ASN1_Tag tag;
};

/**
* This class represents CARs of CVCs. (String tagged with 2)
*/
class ASN1_Car : public ASN1_EAC_String
{
	public:
		/**
		* Create a CAR with the specified content.
		* @param str the CAR value
		*/
		ASN1_Car(string const& str = "");
};

/**
* This class represents CHRs of CVCs (tag 32)
*/
class ASN1_Chr : public ASN1_EAC_String
{
	public:
		/**
		* Create a CHR with the specified content.
		* @param str the CHR value
		*/
		ASN1_Chr(string const& str = "");
};

/*
* Comparison Operations
*/
bool operator==(in EAC_Time, const EAC_Time&);
bool operator!=(in EAC_Time, const EAC_Time&);
bool operator<=(in EAC_Time, const EAC_Time&);
bool operator>=(in EAC_Time, const EAC_Time&);
bool operator>(in EAC_Time, const EAC_Time&);
bool operator<(in EAC_Time, const EAC_Time&);

bool operator==(in ASN1_EAC_String, const ASN1_EAC_String&);
 bool operator!=(in ASN1_EAC_String lhs, const ASN1_EAC_String& rhs)
{
	return !(lhs == rhs);
}