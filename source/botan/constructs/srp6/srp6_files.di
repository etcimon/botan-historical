/*
* SRP-6a File Handling
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/bigint.h>
#include <string>
#include <map>
/**
* A GnuTLS compatible SRP6 authenticator file
*/
class SRP6_Authenticator_File
{
	public:
		/**
		* @param filename will be opened and processed as a SRP
		* authenticator file
		*/
		SRP6_Authenticator_File(in string filename);

		bool lookup_user(in string username,
							  ref BigInt v,
							  Vector!( byte )& salt,
							  string& group_id) const;
	private:
		struct SRP6_Data
		{
			SRP6_Data() {}

			SRP6_Data(in BigInt v,
						 in Vector!byte salt,
						 in string group_id) :
				v(v), salt(salt), group_id(group_id) {}

			BigInt v;
			Vector!( byte ) salt;
			string group_id;
		};

		std::map<string, SRP6_Data> entries;
};