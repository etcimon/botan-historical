/*
* DataSink
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/filter.h>
#include <iosfwd>
/**
* This class represents abstract data sink objects.
*/
class DataSink : public Filter
{
	public:
		bool attachable() { return false; }
		DataSink() {}
		abstract ~DataSink() {}

		DataSink& operator=(in DataSink);
		DataSink(in DataSink);
};

/**
* This class represents a data sink which writes its output to a stream.
*/
class DataSink_Stream : public DataSink
{
	public:
		string name() const { return identifier; }

		void write(const byte[], size_t);

		/**
		* Construct a DataSink_Stream from a stream.
		* @param stream the stream to write to
		* @param name identifier
		*/
		DataSink_Stream(std::ostream& stream,
							 in string name = "<std::ostream>");

		/**
		* Construct a DataSink_Stream from a stream.
		* @param pathname the name of the file to open a stream to
		* @param use_binary indicates whether to treat the file
		* as a binary file or not
		*/
		DataSink_Stream(in string pathname,
							 bool use_binary = false);

		~DataSink_Stream();
	private:
		const string identifier;

		std::ostream* sink_p;
		std::ostream& sink;
};