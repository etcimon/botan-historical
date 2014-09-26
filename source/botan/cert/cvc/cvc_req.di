/*
* EAC1_1 CVC Request
* (C) 2008 Falko Strenzke
*	  2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/cvc_gen_cert.h>
/**
* This class represents TR03110 v1.1 EAC CV Certificate Requests.
*/
class EAC1_1_Req : public EAC1_1_gen_CVC<EAC1_1_Req>
{
	public:
		friend class EAC1_1_ADO;
		friend class EAC1_1_obj<EAC1_1_Req>;

		/**
		* Compare for equality with other
		* @param other compare for equality with this object
		*/
		bool operator==(in EAC1_1_Req other) const;

		/**
		* Construct a CVC request from a data source.
		* @param source the data source
		*/
		EAC1_1_Req(DataSource& source);

		/**
		* Construct a CVC request from a DER encoded CVC request file.
		* @param str the path to the DER encoded file
		*/
		EAC1_1_Req(in string str);

		abstract ~EAC1_1_Req(){}
	private:
		void force_decode();
		EAC1_1_Req() {}
};

/*
* Comparison Operator
*/
 bool operator!=(EAC1_1_Req const& lhs, EAC1_1_Req const& rhs)
{
	return !(lhs == rhs);
}