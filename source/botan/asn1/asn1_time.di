/*
* ASN.1 Time Representation
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/asn1_obj.h>
#include <chrono>
/**
* X.509 Time
*/
class X509_Time : public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder&) const;
		void decode_from(class BER_Decoder&);

		string as_string() const;
		string readable_string() const;
		bool time_is_set() const;

		string to_string() const { return readable_string(); }

		s32bit cmp(in X509_Time) const;

		void set_to(in string);
		void set_to(in string, ASN1_Tag);

		X509_Time(in SysTime time);
		X509_Time(in string = "");
		X509_Time(in string, ASN1_Tag);
	private:
		bool passes_sanity_check() const;
		uint year, month, day, hour, minute, second;
		ASN1_Tag tag;
};

/*
* Comparison Operations
*/
bool operator==(in X509_Time, const X509_Time&);
bool operator!=(in X509_Time, const X509_Time&);
bool operator<=(in X509_Time, const X509_Time&);
bool operator>=(in X509_Time, const X509_Time&);
bool operator<(in X509_Time, const X509_Time&);
bool operator>(in X509_Time, const X509_Time&);