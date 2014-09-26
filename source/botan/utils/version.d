/*
* Version Information
* (C) 1999-2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/version.h>
#include <botan/parsing.h>
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
