/*
* SRP-6a File Handling
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_SRP6A_FILES_H__

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
							  BigInt& v,
							  std::vector<byte>& salt,
							  string& group_id) const;
	private:
		struct SRP6_Data
		{
			SRP6_Data() {}

			SRP6_Data(const BigInt& v,
						 in Array!byte salt,
						 in string group_id) :
				v(v), salt(salt), group_id(group_id) {}

			BigInt v;
			std::vector<byte> salt;
			string group_id;
		};

		std::map<string, SRP6_Data> entries;
};