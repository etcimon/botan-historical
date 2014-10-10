/*
* Version Information
* (C) 1999-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.version_;

import botan.types;
import string;
/*
* Get information describing the version
*/

/**
* Get a human-readable string identifying the version of Botan.
* No particular format should be assumed.
* @return version string
*/
string version_string();

/**
* Return the date this version of botan was released, in an integer of
* the form YYYYMMDD. For instance a version released on May 21, 2013
* would return the integer 20130521. If the currently running version
* is not an official release, this function will return 0 instead.
*
* @return release date, or zero if unreleased
*/
uint version_datestamp();

/**
* Get the major version number.
* @return major version number
*/
uint version_major();

/**
* Get the minor version number.
* @return minor version number
*/
uint version_minor();

/**
* Get the patch number.
* @return patch number
*/
uint version_patch();

/*
* Macros for compile-time version checks
*/
#define BOTAN_VERSION_CODE_FOR(a,b,c) ((a << 16) | (b << 8) | (c))

/**
* Compare using BOTAN_VERSION_CODE_FOR, as in
*  # if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,8,0)
*  #	 error "Botan version too old"
*  # endif
*/
#define BOTAN_VERSION_CODE BOTAN_VERSION_CODE_FOR(BOTAN_VERSION_MAJOR, \
																  BOTAN_VERSION_MINOR, \
																  BOTAN_VERSION_PATCH)

import botan.version;
import botan.parsing;
/*
  These are intentionally compiled rather than d, so an
  application running against a shared library can test the true
  version they are running against.
*/

/*
* Return the version as a string
*/
string version_string()
{
#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)
	
	/*
	It is intentional that this string is a compile-time constant;
	it makes it much easier to find in binaries.
	*/
	
	return "Botan " STR(BOTAN_VERSION_MAJOR) "."
		STR(BOTAN_VERSION_MINOR) "."
			STR(BOTAN_VERSION_PATCH) " ("
			BOTAN_VERSION_RELEASE_TYPE
#if (BOTAN_VERSION_DATESTAMP != 0)
			", dated " STR(BOTAN_VERSION_DATESTAMP)
#endif
			", revision " BOTAN_VERSION_VC_REVISION
			", distribution " BOTAN_DISTRIBUTION_INFO ")";
	
#undef STR
#undef QUOTE
}

uint version_datestamp() { return BOTAN_VERSION_DATESTAMP; }

/*
* Return parts of the version as integers
*/
uint version_major() { return BOTAN_VERSION_MAJOR; }
uint version_minor() { return BOTAN_VERSION_MINOR; }
uint version_patch() { return BOTAN_VERSION_PATCH; }

}
