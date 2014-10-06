/*
* Bzip Compressor
* (C) 2001 Peter J Jones
*	  2001-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.filter;
/**
* Bzip Compression Filter
*/
class Bzip_Compression : Filter
{
	public:
		string name() const { return "Bzip_Compression"; }

		void write(in ubyte* input, size_t length);
		void start_msg();
		void end_msg();

		void flush();

		Bzip_Compression(size_t = 9);
		~this() { clear(); }
	private:
		void clear();

		const size_t level;
		SafeVector!ubyte buffer;
		class Bzip_Stream* bz;
};

/**
* Bzip Decompression Filter
*/
class Bzip_Decompression : Filter
{
	public:
		string name() const { return "Bzip_Decompression"; }

		void write(in ubyte* input, size_t length);
		void start_msg();
		void end_msg();

		Bzip_Decompression(bool = false);
		~this() { clear(); }
	private:
		void clear();

		const bool small_mem;
		SafeVector!ubyte buffer;
		class Bzip_Stream* bz;
		bool no_writes;
};