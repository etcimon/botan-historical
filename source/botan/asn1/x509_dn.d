/*
* X509_DN
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/x509_dn.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/parsing.h>
#include <botan/internal/stl_util.h>
#include <botan/oids.h>
#include <ostream>

namespace Botan {

/*
* Create an empty X509_DN
*/
X509_DN::X509_DN()
   {
   }

/*
* Create an X509_DN
*/
X509_DN::X509_DN(const std::multimap<OID, std::string>& args)
   {
   for(auto i = args.begin(); i != args.end(); ++i)
      add_attribute(i->first, i->second);
   }

/*
* Create an X509_DN
*/
X509_DN::X509_DN(const std::multimap<std::string, std::string>& args)
   {
   for(auto i = args.begin(); i != args.end(); ++i)
      add_attribute(OIDS::lookup(i->first), i->second);
   }

/*
* Add an attribute to a X509_DN
*/
void X509_DN::add_attribute(const std::string& type,
                            const std::string& str)
   {
   OID oid = OIDS::lookup(type);
   add_attribute(oid, str);
   }

/*
* Add an attribute to a X509_DN
*/
void X509_DN::add_attribute(const OID& oid, const std::string& str)
   {
   if(str == "")
      return;

   auto range = dn_info.equal_range(oid);
   for(auto i = range.first; i != range.second; ++i)
      if(i->second.value() == str)
         return;

   multimap_insert(dn_info, oid, ASN1_String(str));
   dn_bits.clear();
   }

/*
* Get the attributes of this X509_DN
*/
std::multimap<OID, std::string> X509_DN::get_attributes() const
   {
   std::multimap<OID, std::string> retval;
   for(auto i = dn_info.begin(); i != dn_info.end(); ++i)
      multimap_insert(retval, i->first, i->second.value());
   return retval;
   }

/*
* Get the contents of this X.500 Name
*/
std::multimap<std::string, std::string> X509_DN::contents() const
   {
   std::multimap<std::string, std::string> retval;
   for(auto i = dn_info.begin(); i != dn_info.end(); ++i)
      multimap_insert(retval, OIDS::lookup(i->first), i->second.value());
   return retval;
   }

/*
* Get a single attribute type
*/
std::vector<std::string> X509_DN::get_attribute(const std::string& attr) const
   {
   const OID oid = OIDS::lookup(deref_info_field(attr));

   auto range = dn_info.equal_range(oid);

   std::vector<std::string> values;
   for(auto i = range.first; i != range.second; ++i)
      values.push_back(i->second.value());
   return values;
   }

/*
* Return the BER encoded data, if any
*/
std::vector<byte> X509_DN::get_bits() const
   {
   return dn_bits;
   }

/*
* Deref aliases in a subject/issuer info request
*/
std::string X509_DN::deref_info_field(const std::string& info)
   {
   if(info == "Name" || info == "CommonName") return "X520.CommonName";
   if(info == "SerialNumber")                 return "X520.SerialNumber";
   if(info == "Country")                      return "X520.Country";
   if(info == "Organization")                 return "X520.Organization";
   if(info == "Organizational Unit" || info == "OrgUnit")
      return "X520.OrganizationalUnit";
   if(info == "Locality")                     return "X520.Locality";
   if(info == "State" || info == "Province")  return "X520.State";
   if(info == "Email")                        return "RFC822";
   return info;
   }

/*
* Compare two X509_DNs for equality
*/
bool operator==(const X509_DN& dn1, const X509_DN& dn2)
   {
   auto attr1 = dn1.get_attributes();
   auto attr2 = dn2.get_attributes();

   if(attr1.size() != attr2.size()) return false;

   auto p1 = attr1.begin();
   auto p2 = attr2.begin();

   while(true)
      {
      if(p1 == attr1.end() && p2 == attr2.end())
         break;
      if(p1 == attr1.end())      return false;
      if(p2 == attr2.end())      return false;
      if(p1->first != p2->first) return false;
      if(!x500_name_cmp(p1->second, p2->second))
         return false;
      ++p1;
      ++p2;
      }
   return true;
   }

/*
* Compare two X509_DNs for inequality
*/
bool operator!=(const X509_DN& dn1, const X509_DN& dn2)
   {
   return !(dn1 == dn2);
   }

/*
* Induce an arbitrary ordering on DNs
*/
bool operator<(const X509_DN& dn1, const X509_DN& dn2)
   {
   auto attr1 = dn1.get_attributes();
   auto attr2 = dn2.get_attributes();

   if(attr1.size() < attr2.size()) return true;
   if(attr1.size() > attr2.size()) return false;

   for(auto p1 = attr1.begin(); p1 != attr1.end(); ++p1)
      {
      auto p2 = attr2.find(p1->first);
      if(p2 == attr2.end())       return false;
      if(p1->second > p2->second) return false;
      if(p1->second < p2->second) return true;
      }
   return false;
   }

namespace {

/*
* DER encode a RelativeDistinguishedName
*/
void do_ava(DER_Encoder& encoder,
            const std::multimap<OID, std::string>& dn_info,
            ASN1_Tag string_type, const std::string& oid_str,
            bool must_exist = false)
   {
   const OID oid = OIDS::lookup(oid_str);
   const bool exists = (dn_info.find(oid) != dn_info.end());

   if(!exists && must_exist)
      throw Encoding_Error("X509_DN: No entry for " + oid_str);
   if(!exists) return;

   auto range = dn_info.equal_range(oid);

   for(auto i = range.first; i != range.second; ++i)
      {
      encoder.start_cons(SET)
         .start_cons(SEQUENCE)
            .encode(oid)
            .encode(ASN1_String(i->second, string_type))
         .end_cons()
      .end_cons();
      }
   }

}

/*
* DER encode a DistinguishedName
*/
void X509_DN::encode_into(DER_Encoder& der) const
   {
   auto dn_info = get_attributes();

   der.start_cons(SEQUENCE);

   if(!dn_bits.empty())
      der.raw_bytes(dn_bits);
   else
      {
      do_ava(der, dn_info, PRINTABLE_STRING, "X520.Country");
      do_ava(der, dn_info, DIRECTORY_STRING, "X520.State");
      do_ava(der, dn_info, DIRECTORY_STRING, "X520.Locality");
      do_ava(der, dn_info, DIRECTORY_STRING, "X520.Organization");
      do_ava(der, dn_info, DIRECTORY_STRING, "X520.OrganizationalUnit");
      do_ava(der, dn_info, DIRECTORY_STRING, "X520.CommonName");
      do_ava(der, dn_info, PRINTABLE_STRING, "X520.SerialNumber");
      }

   der.end_cons();
   }

/*
* Decode a BER encoded DistinguishedName
*/
void X509_DN::decode_from(BER_Decoder& source)
   {
   std::vector<byte> bits;

   source.start_cons(SEQUENCE)
      .raw_bytes(bits)
   .end_cons();

   BER_Decoder sequence(bits);

   while(sequence.more_items())
      {
      BER_Decoder rdn = sequence.start_cons(SET);

      while(rdn.more_items())
         {
         OID oid;
         ASN1_String str;

         rdn.start_cons(SEQUENCE)
            .decode(oid)
            .decode(str)
            .verify_end()
        .end_cons();

         add_attribute(oid, str.value());
         }
      }

   dn_bits = bits;
   }

namespace {

std::string to_short_form(const std::string& long_id)
   {
   if(long_id == "X520.CommonName")
      return "CN";

   if(long_id == "X520.Organization")
      return "O";

   if(long_id == "X520.OrganizationalUnit")
      return "OU";

   return long_id;
   }

}

std::ostream& operator<<(std::ostream& out, const X509_DN& dn)
   {
   std::multimap<std::string, std::string> contents = dn.contents();

   for(std::multimap<std::string, std::string>::const_iterator i = contents.begin();
       i != contents.end(); ++i)
      {
      out << to_short_form(i->first) << "=" << i->second << ' ';
      }
   return out;
   }

}
