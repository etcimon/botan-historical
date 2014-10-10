/*
* SRP-6a File Handling
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.srp6_files;
import botan.parsing;
import botan.codec.base64;
import fstream;
SRP6_Authenticator_File::SRP6_Authenticator_File(in string filename)
{
	std::ifstream in(filename.c_str());

	if (!input)
		return; // no entries

	while(in.good())
	{
		string line;
		std::getline(input, line);

		Vector!string parts = split_on(line, ':');

		if (parts.size() != 4)
			throw new Decoding_Error("Invalid line in SRP authenticator file");

		string username = parts[0];
		BigInt v = BigInt::decode(base64_decode(parts[1]));
		Vector!ubyte salt = unlock(base64_decode(parts[2]));
		BigInt group_id_idx = BigInt::decode(base64_decode(parts[3]));

		string group_id;

		if (group_id_idx == 1)
			group_id = "modp/srp/1024";
		else if (group_id_idx == 2)
			group_id = "modp/srp/1536";
		else if (group_id_idx == 3)
			group_id = "modp/srp/2048";
		else
			continue; // unknown group, ignored

		entries[username] = SRP6_Data(v, salt, group_id);
	}
}

bool SRP6_Authenticator_File::lookup_user(in string username,
														ref BigInt v,
														Vector!ubyte& salt,
														string& group_id) const
{
	HashMap<string, SRP6_Data>::const_iterator i = entries.find(username);

	if (i == entries.end())
		return false;

	v = i.second.v;
	salt = i.second.salt;
	group_id = i.second.group_id;

	return true;
}

}
