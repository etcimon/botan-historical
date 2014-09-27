/*
* Version Information
* (C) 1999-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

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