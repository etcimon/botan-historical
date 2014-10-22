/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*	  2001-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.zlib;

import botan.filters.filter;
import botan.utils.exceptn;

import std.c.string;
import std.c.stdio;
import map;
import etc.c.zlib;

/**
* Zlib Compression Filter
*/
final class Zlib_Compression : Filter
{
public:
	@property string name() const { return "Zlib_Compression"; }

	/*
	* Compress Input with Zlib
	*/
	void write(in ubyte* input, size_t length)
	{
		zlib.stream.next_in = cast(ubyte*)input;
		zlib.stream.avail_in = length;
		
		while(zlib.stream.avail_in != 0)
		{
			zlib.stream.next_out = cast(ubyte*)(&buffer[0]);
			zlib.stream.avail_out = buffer.length;
			deflate(&(zlib.stream), Z_NO_FLUSH);
			send(&buffer[0], buffer.length - zlib.stream.avail_out);
		}
	}

	/*
	* Start Compressing with Zlib
	*/
	void start_msg()
	{
		clear();
		zlib = new Zlib_Stream;
		
		int res = deflateInit2(&(zlib.stream),
		                       level,
		                       Z_DEFLATED,
		                       (raw_deflate ? -15 : 15),
		                       8,
		                       Z_DEFAULT_STRATEGY);
		
		if (res == Z_STREAM_ERROR)
			throw new Invalid_Argument("Bad setting in deflateInit2");
		else if (res != Z_OK)
			throw new Memory_Exhaustion();
	}

	/*
	* Finish Compressing with Zlib
	*/
	void end_msg()
	{
		zlib.stream.next_in = 0;
		zlib.stream.avail_in = 0;
		
		int rc = Z_OK;
		while(rc != Z_STREAM_END)
		{
			zlib.stream.next_out = cast(ubyte*)(&buffer[0]);
			zlib.stream.avail_out = buffer.length;
			
			rc = deflate(&(zlib.stream), Z_FINISH);
			send(&buffer[0], buffer.length - zlib.stream.avail_out);
		}
		
		clear();
	}

	/**
	* Flush the compressor
	*/
	void flush()
	{
		zlib.stream.next_in = 0;
		zlib.stream.avail_in = 0;
		
		while(true)
		{
			zlib.stream.avail_out = buffer.length;
			zlib.stream.next_out = cast(ubyte*)(&buffer[0]);
			
			deflate(&(zlib.stream), Z_FULL_FLUSH);
			send(&buffer[0], buffer.length - zlib.stream.avail_out);
			
			if (zlib.stream.avail_out == buffer.length)
				break;
		}
	}

	/**
	* @param _level how much effort to use on compressing (0 to 9);
	*		  higher levels are slower but tend to give better
	*		  compression
	* @param _raw_deflate if true no zlib header/trailer will be used
	*/
	this(size_t _level = 6, bool _raw_deflate = false)
	{
		
		level = (_level >= 9) ? 9 : _level;
		raw_deflate = _raw_deflate;
		buffer = DEFAULT_BUFFERSIZE;
		zlib = 0;
	}

	~this() { clear(); }
private:
	/*
	* Clean up Compression Context
	*/
	void clear()
	{
		zeroise(buffer);
		
		if (zlib)
		{
			deflateEnd(&(zlib.stream));
			delete zlib;
			zlib = 0;
		}
	}

	const size_t level;
	const bool raw_deflate;

	SafeVector!ubyte buffer;
	Zlib_Stream* zlib;
};

/**
* Zlib Decompression Filter
*/
final class Zlib_Decompression : Filter
{
public:
	@property string name() const { return "Zlib_Decompression"; }

	/*
	* Decompress Input with Zlib
	*/
	void write(in ubyte* input_arr, size_t length)
	{
		if (length) no_writes = false;
		
		// non-const needed by zlib api :(
		ubyte* input = cast(ubyte*)(input_arr);
		
		zlib.stream.next_in = input;
		zlib.stream.avail_in = length;
		
		while(zlib.stream.avail_in != 0)
		{
			zlib.stream.next_out = cast(ubyte*)(&buffer[0]);
			zlib.stream.avail_out = buffer.length;
			
			int rc = inflate(&(zlib.stream), Z_SYNC_FLUSH);
			
			if (rc != Z_OK && rc != Z_STREAM_END)
			{
				clear();
				if (rc == Z_DATA_ERROR)
					throw new Decoding_Error("Zlib_Decompression: Data integrity error");
				else if (rc == Z_NEED_DICT)
					throw new Decoding_Error("Zlib_Decompression: Need preset dictionary");
				else if (rc == Z_MEM_ERROR)
					throw new Memory_Exhaustion();
				else
					throw new Exception("Zlib decompression: Unknown error");
			}
			
			send(&buffer[0], buffer.length - zlib.stream.avail_out);
			
			if (rc == Z_STREAM_END)
			{
				size_t read_from_block = length - zlib.stream.avail_in;
				start_msg();
				
				zlib.stream.next_in = input + read_from_block;
				zlib.stream.avail_in = length - read_from_block;
				
				input += read_from_block;
				length -= read_from_block;
			}
		}
	}

	/*
	* Start Decompressing with Zlib
	*/
	void start_msg()
	{
		clear();
		zlib = new Zlib_Stream;
		
		if (inflateInit2(&(zlib.stream), (raw_deflate ? -15 : 15)) != Z_OK)
			throw new Memory_Exhaustion();
	}

	/*
	* Finish Decompressing with Zlib
	*/
	void end_msg()
	{
		if (no_writes) return;
		zlib.stream.next_in = 0;
		zlib.stream.avail_in = 0;
		
		int rc = Z_OK;
		
		while(rc != Z_STREAM_END)
		{
			zlib.stream.next_out = cast(ubyte*)(&buffer[0]);
			zlib.stream.avail_out = buffer.length;
			rc = inflate(&(zlib.stream), Z_SYNC_FLUSH);
			
			if (rc != Z_OK && rc != Z_STREAM_END)
			{
				clear();
				throw new Decoding_Error("Zlib_Decompression: Error finalizing");
			}
			
			send(&buffer[0], buffer.length - zlib.stream.avail_out);
		}
		
		clear();
	}


	/*
	* Zlib_Decompression Constructor
	*/
	this(bool _raw_deflate = false)
	{
		raw_deflate = _raw_deflate;
		buffer = DEFAULT_BUFFERSIZE;
		zlib = 0;
		no_writes = true;
	}

	~this() { clear(); }
private:
	void clear();

	const bool raw_deflate;

	SafeVector!ubyte buffer;
	Zlib_Stream* zlib;
	bool no_writes;
};


/*
* Allocation Information for Zlib
*/
class Zlib_Alloc_Info
{
public:
	HashMap!(void*, size_t) current_allocs;
};

/*
* Allocation Function for Zlib
*/
void* zlib_malloc(void* info_ptr, uint n, uint size)
{
	Zlib_Alloc_Info* info = cast(Zlib_Alloc_Info*)(info_ptr);
	
	const size_t total_sz = n * size;
	
	void* ptr = malloc(total_sz);
	info.current_allocs[ptr] = total_sz;
	return ptr;
}

/*
* Allocation Function for Zlib
*/
void zlib_free(void* info_ptr, void* ptr)
{
	Zlib_Alloc_Info* info = cast(Zlib_Alloc_Info*)(info_ptr);
	auto i = info.current_allocs.find(ptr);
	if (i == info.current_allocs.end())
		throw new Invalid_Argument("zlib_free: Got pointer not allocated by us");
	
	memset(ptr, 0, i.second);
	free(ptr);
}

/**
* Wrapper Type for Zlib z_stream
*/
class Zlib_Stream
{
public:
	/**
	* Underlying stream
	*/
	z_stream stream;
	
	/**
	* Constructor
	*/
	this()
	{
		memset(&stream, 0, (z_stream).sizeof);
		stream.zalloc = zlib_malloc;
		stream.zfree = zlib_free;
		stream.opaque = new Zlib_Alloc_Info;
	}
	
	/**
	* Destructor
	*/
	~this()
	{
		Zlib_Alloc_Info* info = cast(Zlib_Alloc_Info*)(stream.opaque);
		delete info;
		memset(&stream, 0, (z_stream).sizeof);
	}
};






/*
* Clean up Decompression Context
*/
void clear()
{
	zeroise(buffer);
	
	no_writes = true;
	
	if (zlib)
	{
		inflateEnd(&(zlib.stream));
		delete zlib;
		zlib = 0;
	}
}

}
