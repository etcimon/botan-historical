/*
* DataSink
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.filter;
import iosfwd;
/**
* This class represents abstract data sink objects.
*/
class DataSink : Filter
{
	public:
		bool attachable() { return false; }
		DataSink() {}
		~this() {}

		DataSink& operator=(in DataSink);
		DataSink(in DataSink);
};

/**
* This class represents a data sink which writes its output to a stream.
*/
class DataSink_Stream : DataSink
{
	public:
		string name() const { return identifier; }

		void write(in ubyte*, size_t);

		/**
		* Construct a DataSink_Stream from a stream.
		* @param stream the stream to write to
		* @param name identifier
		*/
		DataSink_Stream(ref std.ostream stream,
							 in string name = "<std.ostream>");

		/**
		* Construct a DataSink_Stream from a stream.
		* @param pathname the name of the file to open a stream to
		* @param use_binary indicates whether to treat the file
		* as a binary file or not
		*/
		DataSink_Stream(in string pathname,
							 bool use_binary = false);

		~this();
	private:
		const string identifier;

		std.ostream* sink_p;
		ref std.ostream sink;
};