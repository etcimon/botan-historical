/*
* Version Information
* (C) 1999-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.version_;

import botan.constants;
import botan.utils.types;
import string;
import botan.parsing;
/*
 * These are intentionally compiled so an application running against a 
 * shared library can test the true version they are running against.
*/

/**
* Get a human-readable string identifying the version of Botan.
* No particular format should be assumed.
* @return version string
*/
string version_string()
{
		
	/*
	It is intentional that this string is a compile-time constant;
	it makes it much easier to find in binaries.
	*/
	return "Botan " ~ BOTAN_VERSION_MAJOR ~ "."
			~ BOTAN_VERSION_MINOR ~ "." 
			~ BOTAN_VERSION_PATCH ~ " ("
			~ BOTAN_VERSION_RELEASE_TYPE
			~ ", dated " ~ BOTAN_VERSION_DATESTAMP
			~ ", revision " ~ BOTAN_VERSION_VC_REVISION
			~ ", distribution " ~ BOTAN_DISTRIBUTION_INFO ~ ")";
}

/**
* Return the date this version of botan was released, in an integer of
* the form YYYYMMDD. For instance a version released on May 21, 2013
* would return the integer 20130521. If the currently running version
* is not an official release, this function will return 0 instead.
*
* @return release date, or zero if unreleased
*/
uint version_datestamp() { return BOTAN_VERSION_DATESTAMP; }

/**
* Get the major version number.
* @return major version number
*/
uint version_major() { return BOTAN_VERSION_MAJOR; }

/**
* Get the minor version number.
* @return minor version number
*/
uint version_minor() { return BOTAN_VERSION_MINOR; }

/**
* Get the patch number.
* @return patch number
*/
uint version_patch() { return BOTAN_VERSION_PATCH; }

/*
* Allows compile-time version checks
*/
long BOTAN_VERSION_CODE_FOR(ubyte a, ubyte b, ubyte c) {
	return ((a << 16) | (b << 8) | (c));
}

/**
* Compare using BOTAN_VERSION_CODE_FOR, as in
*  static assert (BOTAN_VERSION_CODE > BOTAN_VERSION_CODE_FOR(1,8,0), "Botan version too old");
*/
static long BOTAN_VERSION_CODE = BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, BOTAN_VERSION_MINOR, BOTAN_VERSION_PATCH);