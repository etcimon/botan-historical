/*
* X.509 Certificate Options
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.x509self;
import botan.asn1.oid_lookup.oids;
import botan.parsing;
import std.datetime;
import std.datetime;
/*
* Set when the certificate should become valid
*/
void X509_Cert_Options::not_before(in string time_string)
{
	start = X509_Time(time_string);
}

/*
* Set when the certificate should expire
*/
void X509_Cert_Options::not_after(in string time_string)
{
	end = X509_Time(time_string);
}

/*
* Set key constraint information
*/
void X509_Cert_Options::add_constraints(Key_Constraints usage)
{
	constraints = usage;
}

/*
* Set key constraint information
*/
void X509_Cert_Options::add_ex_constraint(in OID oid)
{
	ex_constraints.push_back(oid);
}

/*
* Set key constraint information
*/
void X509_Cert_Options::add_ex_constraint(in string oid_str)
{
	ex_constraints.push_back(oids.lookup(oid_str));
}

/*
* Mark this certificate for CA usage
*/
void X509_Cert_Options::CA_key(size_t limit)
{
	is_CA = true;
	path_limit = limit;
}

/*
* Do basic sanity checks
*/
void X509_Cert_Options::sanity_check() const
{
	if (common_name == "" || country == "")
		throw new Encoding_Error("X.509 certificate: name and country MUST be set");
	if (country.size() != 2)
		throw new Encoding_Error("Invalid ISO country code: " ~ country);
	if (start >= end)
		throw new Encoding_Error("X509_Cert_Options: invalid time constraints");
}

/*
* Initialize the certificate options
*/
X509_Cert_Options::X509_Cert_Options(in string initial_opts,
												 Duration expiration_time)
{
	is_CA = false;
	path_limit = 0;
	constraints = NO_CONSTRAINTS;

	auto now = Clock.currTime();

	start = X509_Time(now);
	end = X509_Time(now + expiration_time);

	if (initial_opts == "")
		return;

	Vector!string parsed = split_on(initial_opts, '/');

	if (parsed.size() > 4)
		throw new Invalid_Argument("X.509 cert options: Too many names: "
									  + initial_opts);

	if (parsed.size() >= 1) common_name  = parsed[0];
	if (parsed.size() >= 2) country		= parsed[1];
	if (parsed.size() >= 3) organization = parsed[2];
	if (parsed.size() == 4) org_unit	  = parsed[3];
}

}
