/*
* SRP-6a File Handling
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.srp6_files;

import botan.math.bigint.bigint;
import botan.srp6_files;
import botan.utils.parsing;
import botan.codec.base64;
import fstream;
import string;
import map;
import std.stdio;

/**
* A GnuTLS compatible SRP6 authenticator file
*/
final class SRP6_Authenticator_File
{
public:
	/**
	* @param filename will be opened and processed as a SRP
	* authenticator file
	*/
	this(in string filename)
	{
		auto file = File(filename);
		auto range = file.byLine();
		
		foreach (line; range) {	
			import std.array : array;
			string[] parts = cast(string[]) splitter(line, ':').array;
			
			if (parts.length != 4)
				throw new Decoding_Error("Invalid line in SRP authenticator file");
			
			string username = parts[0];
			BigInt v = BigInt.decode(base64_decode(parts[1]));
			Vector!ubyte salt = unlock(base64_decode(parts[2]));
			BigInt group_id_idx = BigInt.decode(base64_decode(parts[3]));
			
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

	bool lookup_user(in string username,
	                 ref BigInt v,
	              	 ref Vector!ubyte salt,
	                 ref string group_id) const
	{
		SRP6_Data entry = entries.get(username);
		if (entry == SRP6_Data.init)
			return false;

		v = entry.v;
		salt = entry.salt;
		group_id = entry.group_id;
		
		return true;
	}

private:
	struct SRP6_Data
	{

		this(in BigInt _v,
			 in Vector!ubyte _salt,
			 in string _group_id) 
		{
			v = _v;
			salt = _salt; 
			group_id = _group_id;
		}

		BigInt v;
		Vector!ubyte salt;
		string group_id;
	};

	HashMap!(string, SRP6_Data) entries;
};