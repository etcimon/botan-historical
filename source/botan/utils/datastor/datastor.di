/*
* Data Store
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.alloc.secmem;
import functional;
import utility;
import string;
import vector;
import map;
/**
* Data Store
*/
class Data_Store
{
	public:
		/**
		* A search function
		*/
		bool operator==(in Data_Store) const;

		MultiMap!(string, string) search_for(
			bool delegate(string, string) predicate) const;

		Vector!string get(in string) const;

		string get1(in string key) const;

		string get1(in string key,
							  in string default_value) const;

		Vector!byte get1_memvec(in string) const;
		uint get1_uint(in string, uint = 0) const;

		bool has_value(in string) const;

		void add(in MultiMap!(string, string));
		void add(in string, in string);
		void add(in string, uint);
		void add(in string, in SafeVector!byte);
		void add(in string, in Vector!byte);
	private:
		MultiMap!(string, string) contents;
};