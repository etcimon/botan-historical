/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*	  2001-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.filter;
/**
* Zlib Compression Filter
*/
class Zlib_Compression : Filter
{
	public:
		string name() const { return "Zlib_Compression"; }

		void write(in ubyte* input, size_t length);
		void start_msg();
		void end_msg();

		/**
		* Flush the compressor
		*/
		void flush();

		/**
		* @param level how much effort to use on compressing (0 to 9);
		*		  higher levels are slower but tend to give better
		*		  compression
		* @param raw_deflate if true no zlib header/trailer will be used
		*/
		Zlib_Compression(size_t level = 6,
							  bool raw_deflate = false);

		~this() { clear(); }
	private:
		void clear();
		const size_t level;
		const bool raw_deflate;

		SafeVector!ubyte buffer;
		class Zlib_Stream* zlib;
};

/**
* Zlib Decompression Filter
*/
class Zlib_Decompression : Filter
{
	public:
		string name() const { return "Zlib_Decompression"; }

		void write(in ubyte* input, size_t length);
		void start_msg();
		void end_msg();

		Zlib_Decompression(bool raw_deflate = false);
		~this() { clear(); }
	private:
		void clear();

		const bool raw_deflate;

		SafeVector!ubyte buffer;
		class Zlib_Stream* zlib;
		bool no_writes;
};