/*
* OID Registry
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.asn1_oid;
namespace OIDS {

/**
* Register an OID to string mapping.
* @param oid the oid to register
* @param name the name to be associated with the oid
*/
void add_oid(in OID oid, in string name);

void add_oid2str(in OID oid, in string name);
void add_str2oid(in OID oid, in string name);

void add_oidstr(string oidstr, string name);

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
string lookup(in OID oid);

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
bool name_of(in OID oid, in string name);

void set_defaults();

}