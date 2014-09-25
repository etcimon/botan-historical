/*
* Data Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_DATA_STORE_H__

#include <botan/secmem.h>
#include <functional>
#include <utility>
#include <string>
#include <vector>
#include <map>
/**
* Data Store
*/
class Data_Store
{
	public:
		/**
		* A search function
		*/
		bool operator==(const Data_Store&) const;

		std::multimap<string, string> search_for(
			std::function<bool (string, string)> predicate) const;

		std::vector<string> get(in string) const;

		string get1(in string key) const;

		string get1(in string key,
							  in string default_value) const;

		std::vector<byte> get1_memvec(in string) const;
		u32bit get1_u32bit(in string, u32bit = 0) const;

		bool has_value(in string) const;

		void add(const std::multimap<string, string>&);
		void add(in string, in string);
		void add(in string, u32bit);
		void add(in string, in SafeArray!byte);
		void add(in string, in Array!byte);
	private:
		std::multimap<string, string> contents;
};