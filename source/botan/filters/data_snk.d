/*
* DataSink
* (C) 1999-2007 Jack Lloyd
*	  2005 Matthew Gregan
*
* Distributed under the terms of the Botan license
*/

import botan.data_snk;
import botan.exceptn;
import fstream;
/*
* Write to a stream
*/
void DataSink_Stream::write(in byte* output, size_t length)
{
	sink.write(cast(string)(output), length);
	if (!sink.good())
		throw new Stream_IO_Error("DataSink_Stream: Failure writing to " +
									 identifier);
}

/*
* DataSink_Stream Constructor
*/
DataSink_Stream::DataSink_Stream(std::ostream& output,
											in string name) :
	identifier(name),
	sink_p(null),
	sink(output)
{
}

/*
* DataSink_Stream Constructor
*/
DataSink_Stream::DataSink_Stream(in string path,
											bool use_binary) :
	identifier(path),
	sink_p(new std::ofstream(
				 path.c_str(),
				 use_binary ? std::ios::binary : std::ios::out)),
	sink(*sink_p)
{
	if (!sink.good())
	{
		delete sink_p;
		throw new Stream_IO_Error("DataSink_Stream: Failure opening " + path);
	}
}

/*
* DataSink_Stream Destructor
*/
DataSink_Stream::~DataSink_Stream()
{
	delete sink_p;
}

}
