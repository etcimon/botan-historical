/*
* OID Registry
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_OIDS_H__

#include <botan/asn1_oid.h>
namespace OIDS {

/**
* Register an OID to string mapping.
* @param oid the oid to register
* @param name the name to be associated with the oid
*/
void add_oid(const OID& oid, in string name);

void add_oid2str(const OID& oid, in string name);
void add_str2oid(const OID& oid, in string name);

void add_oidstr(const char* oidstr, const char* name);

/**
* See if an OID exists in the internal table.
* @param oid the oid to check for
* @return true if the oid is registered
*/
bool have_oid(in string oid);

/**
* Resolve an OID
* @param oid the OID to look up
* @return name associated with this OID
*/
string lookup(const OID& oid);

/**
* Find the OID to a name. The lookup will be performed in the
* general OID section of the configuration.
* @param name the name to resolve
* @return OID associated with the specified name
*/
OID lookup(in string name);

/**
* Tests whether the specified OID stands for the specified name.
* @param oid the OID to check
* @param name the name to check
* @return true if the specified OID stands for the specified name
*/
bool name_of(const OID& oid, in string name);

void set_defaults();

}