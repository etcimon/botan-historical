/*
* Lzma Compressor
* (C) 2001 Peter J Jones
*	  2001-2007 Jack Lloyd
*	  2012 Vojtech Kral
*
* Distributed under the terms of the botan license.
*/
module botan.filters.lzma;
import botan.filters.filter;

import botan.utils.exceptn;

import std.c.string;
import std.c.stdlib;
import map;

/**
* Lzma Compression Filter
*/
final class Lzma_Compression : Filter
{
public:
	@property string name() const { return "Lzma_Compression"; }

	/*
	* Compress Input with Lzma
	*/
	void write(in ubyte* input, size_t length)
	{
		lzma.stream.next_in = cast(const uint8_t*)(input);
		lzma.stream.avail_in = length;
		
		while(lzma.stream.avail_in != 0)
		{
			lzma.stream.next_out = cast(uint8_t*)(&buffer[0]);
			lzma.stream.avail_out = buffer.length;
			
			lzma_ret ret = lzma_code(&(lzma.stream), LZMA_RUN);
			
			if (ret == LZMA_MEM_ERROR)
				throw new Memory_Exhaustion();
			else if (ret != LZMA_OK)
				throw new Exception("Lzma compression: Error writing");
			
			send(&buffer[0], buffer.length - lzma.stream.avail_out);
		}
	}

	/*
	* Start Compressing with Lzma
	*/
	void start_msg()
	{
		clear();
		lzma = new Lzma_Stream;
		
		lzma_ret ret = lzma_easy_encoder(&(lzma.stream), level, LZMA_CHECK_CRC64);
		
		if (ret == LZMA_MEM_ERROR)
			throw new Memory_Exhaustion();
		else if (ret != LZMA_OK)
			throw new Invalid_Argument("Bad setting in lzma_easy_encoder");
	}

	/*
	* Finish Compressing with Lzma
	*/
	void end_msg()
	{
		lzma.stream.next_in = 0;
		lzma.stream.avail_in = 0;
		
		int ret = LZMA_OK;
		while(ret != LZMA_STREAM_END)
		{
			lzma.stream.next_out = cast(uint8_t*)(&buffer[0]);
			lzma.stream.avail_out = buffer.length;
			
			ret = lzma_code(&(lzma.stream), LZMA_FINISH);
			send(&buffer[0], buffer.length - lzma.stream.avail_out);
		}
		
		clear();
	}

	/**
	* Flush the compressor
	*/
	void flush()
	{
		lzma.stream.next_in = 0;
		lzma.stream.avail_in = 0;
		
		while(true)
		{
			lzma.stream.next_out = cast(uint8_t*)(&buffer[0]);
			lzma.stream.avail_out = buffer.length;
			
			lzma_ret ret = lzma_code(&(lzma.stream), LZMA_FULL_FLUSH);
			
			if (ret == LZMA_MEM_ERROR)
				throw new Memory_Exhaustion();
			else if (ret != LZMA_OK && ret != LZMA_STREAM_END)
				throw new Exception("Lzma compression: Error flushing");
			
			send(&buffer[0], buffer.length - lzma.stream.avail_out);
			
			if (lzma.stream.avail_out == buffer.length)
				break;
		}
	}

	/**
	* @param level how much effort to use on compressing (0 to 9);
	*		  higher levels are slower but tend to give better
	*		  compression
	*/
	this(size_t l = 6)
	{
		level = (l >= 9) ? 9 : l;
		buffer = DEFAULT_BUFFERSIZE;
		lzma = 0;
	}

	~this() { clear(); }
private:
	void clear()
	{
		zeroise(buffer);
		
		if (lzma)
		{
			lzma_end(&(lzma.stream));
			delete lzma;
			lzma = 0;
		}
	}
	const size_t level;

	Secure_Vector!ubyte buffer;
	Lzma_Stream* lzma;
};

/**
* Lzma Decompression Filter
*/
final class Lzma_Decompression : Filter
{
public:
	@property string name() const { return "Lzma_Decompression"; }

	/*
	* Decompress Input with Lzma
	*/
	void write(in ubyte* input_arr, size_t length)
	{
		if (length) no_writes = false;
		
		const uint8_t* input = cast(const uint8_t*)(input_arr);
		
		lzma.stream.next_in = input;
		lzma.stream.avail_in = length;
		
		while(lzma.stream.avail_in != 0)
		{
			lzma.stream.next_out = cast(uint8_t*)(&buffer[0]);
			lzma.stream.avail_out = buffer.length;
			
			lzma_ret ret = lzma_code(&(lzma.stream), LZMA_RUN);
			
			if (ret != LZMA_OK && ret != LZMA_STREAM_END)
			{
				clear();
				if (ret == LZMA_DATA_ERROR)
					throw new Decoding_Error("Lzma_Decompression: Data integrity error");
				else if (ret == LZMA_MEM_ERROR)
					throw new Memory_Exhaustion();
				else
					throw new Exception("Lzma decompression: Unknown error");
			}
			
			send(&buffer[0], buffer.length - lzma.stream.avail_out);
			
			if (ret == LZMA_STREAM_END)
			{
				size_t read_from_block = length - lzma.stream.avail_in;
				start_msg();
				
				lzma.stream.next_in = input + read_from_block;
				lzma.stream.avail_in = length - read_from_block;
				
				input += read_from_block;
				length -= read_from_block;
			}
		}
	}

	/*
	* Start Decompressing with Lzma
	*/
	void start_msg()
	{
		clear();
		lzma = new Lzma_Stream;
		
		lzma_ret ret = lzma_stream_decoder(&(lzma.stream), UINT64_MAX, LZMA_TELL_UNSUPPORTED_CHECK | LZMA_CONCATENATED);
		
		if (ret == LZMA_MEM_ERROR)
			throw new Memory_Exhaustion();
		else if (ret != LZMA_OK)
			throw new Invalid_Argument("Bad setting in lzma_stream_decoder");
	}

	/*
	* Finish Decompressing with Lzma
	*/
	void end_msg()
	{
		if (no_writes) return;
		lzma.stream.next_in = 0;
		lzma.stream.avail_in = 0;
		
		int ret = LZMA_OK;
		
		while(ret != LZMA_STREAM_END)
		{
			lzma.stream.next_out = cast(uint8_t*)(&buffer[0]);
			lzma.stream.avail_out = buffer.length;
			ret = lzma_code(&(lzma.stream), LZMA_FINISH);
			
			if (ret != LZMA_OK && ret != LZMA_STREAM_END)
			{
				clear();
				throw new Decoding_Error("Lzma_Decompression: Error finalizing");
			}
			
			send(&buffer[0], buffer.length - lzma.stream.avail_out);
		}
		
		clear();
	}


	this()
	{
		buffer = DEFAULT_BUFFERSIZE;
		lzma = 0;
		no_writes = true;
	}

	~this() { clear(); }
private:
	/*
	* Clean up Decompression Context
	*/
	void clear()
	{
		zeroise(buffer);
		
		no_writes = true;
		
		if (lzma)
		{
			lzma_end(&(lzma.stream));
			delete lzma;
			lzma = 0;
		}
	}

	Secure_Vector!ubyte buffer;
	Lzma_Stream* lzma;
	bool no_writes;
};

/*
* Allocation Information for Lzma
*/
class Lzma_Alloc_Info
{
public:
	HashMap!(void*, size_t) current_allocs;
};


/**
* Wrapper Type for lzma_stream
*/
class Lzma_Stream
{
public:
	/**
	* Underlying stream
	*/
	lzma_stream stream;
	
	/**
	* Constructor
	*/
	this()
	{
		stream = LZMA_STREAM_INIT;
		stream.allocator = new lzma_allocator;
		stream.allocator.alloc = lzma_malloc;
		stream.allocator.free = lzma_free;
		stream.allocator.opaque = new Lzma_Alloc_Info;
	}
	
	/**
	* Destructor
	*/
	~this()
	{
		Lzma_Alloc_Info* info = cast(Lzma_Alloc_Info*)(stream.allocator.opaque);
		delete info;
		delete stream.allocator;
		memset(&stream, 0, (lzma_stream).sizeof);
	}
};


private:

/*
* Allocation Function for Lzma
*/
void* lzma_malloc(void *opaque, size_t /*nmemb*/, size_t size)
{
	Lzma_Alloc_Info* info = cast(Lzma_Alloc_Info*)(opaque);
	void* ptr = malloc(size);		// It is guaranteed by liblzma doc that nmemb is always set to 1
	info.current_allocs[ptr] = size;
	return ptr;
}

/*
* Allocation Function for Lzma
*/
void lzma_free(void *opaque, void *ptr)
{
	if (!ptr) return;		 // liblzma sometimes does pass zero ptr
	
	Lzma_Alloc_Info* info = cast(Lzma_Alloc_Info*)(opaque);
	auto i = info.current_allocs.find(ptr);
	if (i == info.current_allocs.end())
		throw new Invalid_Argument("lzma_free: Got pointer not allocated by us");
	
	memset(ptr, 0, i.second);
	free(ptr);
}

extern(C) nothrow @nogc:
//TODO: initialize fields to void?
struct lzma_block
{
	uint version_;
	uint header_size;
	enum LZMA_BLOCK_HEADER_SIZE_MIN = 8;
	enum LZMA_BLOCK_HEADER_SIZE_MAX = 1024;
	lzma_check check;	
	lzma_vli compressed_size;	
	lzma_vli uncompressed_size;	
	lzma_filter *filters;	
	ubyte[LZMA_CHECK_SIZE_MAX] raw_check;	
	void *reserved_ptr1;
	void *reserved_ptr2;
	void *reserved_ptr3;
	uint reserved_int1;
	uint reserved_int2;
	lzma_vli reserved_int3;
	lzma_vli reserved_int4;
	lzma_vli reserved_int5;
	lzma_vli reserved_int6;
	lzma_vli reserved_int7;
	lzma_vli reserved_int8;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	lzma_reserved_enum reserved_enum4;
	lzma_bool reserved_bool1;
	lzma_bool reserved_bool2;
	lzma_bool reserved_bool3;
	lzma_bool reserved_bool4;
	lzma_bool reserved_bool5;
	lzma_bool reserved_bool6;
	lzma_bool reserved_bool7;
	lzma_bool reserved_bool8;
}
template lzma_block_header_size_decode(uint b)
{
	enum lzma_block_header_size_decode = (b+1)*4;
}
lzma_ret lzma_block_header_size(lzma_block *block);
lzma_ret lzma_block_header_encode(const (lzma_block)* block, ubyte* out_);
lzma_ret lzma_block_header_decode(lzma_block* block,
                                  lzma_allocator* allocator, const(ubyte)* in_);
lzma_ret lzma_block_compressed_size(
	lzma_block* block, lzma_vli unpadded_size);
lzma_vli lzma_block_unpadded_size(const lzma_block* block);
pure lzma_vli lzma_block_total_size(const(lzma_block*) block);
lzma_ret lzma_block_encoder(
	lzma_stream* strm, lzma_block* block);
lzma_ret lzma_block_decoder(
	lzma_stream *strm, lzma_block *block);
size_t lzma_block_buffer_bound(size_t uncompressed_size);
lzma_ret lzma_block_buffer_encode(
	lzma_block *block, lzma_allocator *allocator,
	const(ubyte)* in_, size_t in_size,
	ubyte* out_, size_t *out_pos, size_t out_size);
lzma_ret lzma_block_buffer_decode(
	lzma_block *block, lzma_allocator *allocator,
	const(ubyte)* in_, size_t *in_pos, size_t in_size,
	ubyte* out_, size_t *out_pos, size_t out_size);
enum LZMA_FILTER_X86 = 0x04UL;

enum LZMA_FILTER_POWERPC = 0x05UL;
enum LZMA_FILTER_IA64 = 0x06UL;
enum LZMA_FILTER_ARM = 0x07UL;
enum LZMA_FILTER_ARMTHUMB = 0x08UL;
enum LZMA_FILTER_SPARC = 0x09UL;
struct lzma_options_bcj
{
	
	uint start_offset;
}


alias bool lzma_bool;
enum lzma_reserved_enum
{
	LZMA_RESERVED_ENUM      = 0
}
enum lzma_ret
{
	LZMA_OK                 = 0,
	LZMA_STREAM_END         = 1,
	LZMA_NO_CHECK           = 2,
	LZMA_UNSUPPORTED_CHECK  = 3,
	LZMA_GET_CHECK          = 4,
	LZMA_MEM_ERROR          = 5,
	LZMA_MEMLIMIT_ERROR     = 6,
	LZMA_FORMAT_ERROR       = 7,
	LZMA_OPTIONS_ERROR      = 8,
	LZMA_DATA_ERROR         = 9,
	LZMA_BUF_ERROR          = 10,
	LZMA_PROG_ERROR         = 11,
}
enum lzma_action
{
	LZMA_RUN = 0,
	LZMA_SYNC_FLUSH = 1,
	LZMA_FULL_FLUSH = 2,
	LZMA_FINISH = 3
}
struct lzma_allocator
{
	void* function(void *opaque, size_t nmemb, size_t size) alloc;
	void function(void *opaque, void *ptr) free;
	void *opaque;
}
struct lzma_internal {}
struct lzma_stream
{
	const(ubyte)* next_in;
	
	size_t avail_in;
	
	ulong total_in;
	ubyte* next_out;
	
	size_t avail_out;
	
	ulong total_out;
	
	lzma_allocator *allocator;
	
	lzma_internal *internal;
	
	void *reserved_ptr1;
	void *reserved_ptr2;
	void *reserved_ptr3;
	void *reserved_ptr4;
	ulong reserved_int1;
	ulong reserved_int2;
	size_t reserved_int3;
	size_t reserved_int4;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
}
//
@property lzma_stream LZMA_STREAM_INIT(){ return lzma_stream.init; };
lzma_ret lzma_code(lzma_stream *strm, lzma_action action);
void lzma_end(lzma_stream *strm);
pure ulong lzma_memusage(const lzma_stream *strm);
pure ulong lzma_memlimit_get(const lzma_stream *strm);
lzma_ret lzma_memlimit_set(lzma_stream *strm, ulong memlimit);

enum lzma_check
{
	LZMA_CHECK_NONE     = 0,
	LZMA_CHECK_CRC32    = 1,
	LZMA_CHECK_CRC64    = 4,
	LZMA_CHECK_SHA256   = 10
}
enum LZMA_CHECK_ID_MAX = 15;
lzma_bool lzma_check_is_supported(lzma_check check);
uint lzma_check_size(lzma_check check);
enum LZMA_CHECK_SIZE_MAX = 64;
pure uint lzma_crc32(
	const(ubyte)* buf, size_t size, uint crc);
pure ulong lzma_crc64(
	const(ubyte)* buf, size_t size, ulong crc);
lzma_check lzma_get_check(const lzma_stream *strm);

enum uint LZMA_PRESET_DEFAULT = 6U;
enum uint LZMA_PRESET_LEVEL_MASK = 0x1FU;
enum uint LZMA_PRESET_EXTREME = (1U << 31);
pure ulong lzma_easy_encoder_memusage(uint preset);
pure ulong lzma_easy_decoder_memusage(uint preset);
lzma_ret lzma_easy_encoder(
	lzma_stream *strm, uint preset, lzma_check check);
lzma_ret lzma_easy_buffer_encode(
	uint preset, lzma_check check,
	lzma_allocator *allocator, const(ubyte)* in_, size_t in_size,
	ubyte* out_, size_t *out_pos, size_t out_size);
lzma_ret lzma_stream_encoder(lzma_stream *strm,
                             const lzma_filter *filters, lzma_check check);
lzma_ret lzma_alone_encoder(
	lzma_stream *strm, const lzma_options_lzma *options);
size_t lzma_stream_buffer_bound(size_t uncompressed_size);
lzma_ret lzma_stream_buffer_encode(
	lzma_filter *filters, lzma_check check,
	lzma_allocator *allocator, const(ubyte)* in_, size_t in_size,
	ubyte* out_, size_t *out_pos, size_t out_size);
enum uint LZMA_TELL_NO_CHECK = 0x01U;
enum uint  LZMA_TELL_UNSUPPORTED_CHECK = 0x02U;
enum uint LZMA_TELL_ANY_CHECK = 0x04U;
enum uint LZMA_CONCATENATED = 0x08U;
lzma_ret lzma_stream_decoder(
	lzma_stream *strm, ulong memlimit, uint flags);
lzma_ret lzma_auto_decoder(
	lzma_stream *strm, ulong memlimit, uint flags);
lzma_ret lzma_alone_decoder(
	lzma_stream *strm, ulong memlimit);
lzma_ret lzma_stream_buffer_decode(
	ulong *memlimit, uint flags, lzma_allocator *allocator,
	const (ubyte)* in_, size_t *in_pos, size_t in_size,
	ubyte* out_, size_t *out_pos, size_t out_size);

enum LZMA_FILTER_DELTA = 0x03UL;
enum lzma_delta_type
{
	LZMA_DELTA_TYPE_BYTE
}
struct lzma_options_delta
{
	
	lzma_delta_type type;
	
	uint dist;
	enum LZMA_DELTA_DIST_MIN = 1;
	enum LZMA_DELTA_DIST_MAX = 256;
	
	uint reserved_int1;
	uint reserved_int2;
	uint reserved_int3;
	uint reserved_int4;
	void *reserved_ptr1;
	void *reserved_ptr2;
}

enum LZMA_FILTERS_MAX = 4;
struct lzma_filter
{
	
	lzma_vli id;
	
	void *options;
}
lzma_bool lzma_filter_encoder_is_supported(lzma_vli id);
lzma_bool lzma_filter_decoder_is_supported(lzma_vli id);
lzma_ret lzma_filters_copy(const lzma_filter*src,
                           lzma_filter *dest, lzma_allocator *allocator);
pure ulong lzma_raw_encoder_memusage(const lzma_filter *filters);
pure ulong lzma_raw_decoder_memusage(const lzma_filter *filters);
lzma_ret lzma_raw_encoder(
	lzma_stream *strm, const lzma_filter *filters);
lzma_ret lzma_raw_decoder(
	lzma_stream *strm, const lzma_filter *filters);
lzma_ret lzma_filters_update(
	lzma_stream *strm, const lzma_filter *filters);
lzma_ret lzma_raw_buffer_encode(
	const lzma_filter *filters, lzma_allocator *allocator,
	const(ubyte) *in_, size_t in_size, ubyte *out_,
	size_t *out_pos, size_t out_size);
lzma_ret lzma_raw_buffer_decode(const lzma_filter *filters,
                                lzma_allocator *allocator,
                                const(ubyte) *in_, size_t *in_pos, size_t in_size,
                                ubyte *out_, size_t *out_pos, size_t out_size);
lzma_ret lzma_properties_size(
	uint *size, const lzma_filter *filter);
lzma_ret lzma_properties_encode(
	const lzma_filter *filter, ubyte *props);
lzma_ret lzma_properties_decode(
	lzma_filter *filter, lzma_allocator *allocator,
	const ubyte *props, size_t props_size);
lzma_ret lzma_filter_flags_size(
	uint *size, const lzma_filter *filter);
lzma_ret lzma_filter_flags_encode(const lzma_filter *filter,
                                  ubyte *out_, size_t *out_pos, size_t out_size);
lzma_ret lzma_filter_flags_decode(
	lzma_filter *filter, lzma_allocator *allocator,
	const ubyte *in_, size_t *in_pos, size_t in_size);
ulong lzma_physmem();

struct lzma_index {};
struct lzma_index_iter
{
	struct StreamStruct
	{
		
		const lzma_stream_flags *flags;
		const void *reserved_ptr1;
		const void *reserved_ptr2;
		const void *reserved_ptr3;
		
		lzma_vli number;
		
		lzma_vli block_count;
		
		lzma_vli compressed_offset;
		
		lzma_vli uncompressed_offset;
		
		lzma_vli compressed_size;
		
		lzma_vli uncompressed_size;
		
		lzma_vli padding;
		lzma_vli reserved_vli1;
		lzma_vli reserved_vli2;
		lzma_vli reserved_vli3;
		lzma_vli reserved_vli4;
	}
	StreamStruct stream;
	struct BlockStruct
	{
		
		lzma_vli number_in_file;
		
		lzma_vli compressed_file_offset;
		
		lzma_vli uncompressed_file_offset;
		
		lzma_vli number_in_stream;
		
		lzma_vli compressed_stream_offset;
		
		lzma_vli uncompressed_stream_offset;
		
		lzma_vli uncompressed_size;
		
		lzma_vli unpadded_size;
		
		lzma_vli total_size;
		lzma_vli reserved_vli1;
		lzma_vli reserved_vli2;
		lzma_vli reserved_vli3;
		lzma_vli reserved_vli4;
		const void *reserved_ptr1;
		const void *reserved_ptr2;
		const void *reserved_ptr3;
		const void *reserved_ptr4;
	}
	BlockStruct block;
	
	union InternalData
	{
		const void *p;
		size_t s;
		lzma_vli v;
	}
	InternalData internal[6];
}
enum lzma_index_iter_mode
{
	LZMA_INDEX_ITER_ANY             = 0,
	LZMA_INDEX_ITER_STREAM          = 1,
	LZMA_INDEX_ITER_BLOCK           = 2,
	LZMA_INDEX_ITER_NONEMPTY_BLOCK  = 3
}
ulong lzma_index_memusage(lzma_vli streams, lzma_vli blocks);
ulong lzma_index_memused(const lzma_index *i);
lzma_index* lzma_index_init(lzma_allocator *allocator);
void lzma_index_end(lzma_index *i, lzma_allocator *allocator);
lzma_ret lzma_index_append(
	lzma_index *i, lzma_allocator *allocator,
	lzma_vli unpadded_size, lzma_vli uncompressed_size);
lzma_ret lzma_index_stream_flags(
	lzma_index *i, const lzma_stream_flags *stream_flags);
pure uint lzma_index_checks(const lzma_index *i);
lzma_ret lzma_index_stream_padding(
	lzma_index *i, lzma_vli stream_padding);
pure lzma_vli lzma_index_stream_count(const lzma_index *i);
pure lzma_vli lzma_index_block_count(const lzma_index *i);
pure lzma_vli lzma_index_size(const lzma_index *i);
pure lzma_vli lzma_index_stream_size(const lzma_index *i);
pure lzma_vli lzma_index_total_size(const lzma_index *i);
pure lzma_vli lzma_index_file_size(const lzma_index *i);
pure lzma_vli lzma_index_uncompressed_size(const lzma_index *i);
void lzma_index_iter_init(
	lzma_index_iter *iter, const lzma_index *i);
void lzma_index_iter_rewind(lzma_index_iter *iter);
lzma_bool lzma_index_iter_next(
	lzma_index_iter *iter, lzma_index_iter_mode mode);
lzma_bool lzma_index_iter_locate(
	lzma_index_iter *iter, lzma_vli target);
lzma_ret lzma_index_cat(
	lzma_index *dest, lzma_index *src, lzma_allocator *allocator);
lzma_index * lzma_index_dup(
	const lzma_index *i, lzma_allocator *allocator);
lzma_ret lzma_index_encoder(
	lzma_stream *strm, const lzma_index *i);
lzma_ret lzma_index_decoder(
	lzma_stream *strm, lzma_index **i, ulong memlimit);
lzma_ret lzma_index_buffer_encode(const lzma_index *i,
                                  ubyte *out_, size_t *out_pos, size_t out_size);
lzma_ret lzma_index_buffer_decode(lzma_index **i,
                                  ulong *memlimit, lzma_allocator *allocator,
                                  const ubyte *in_, size_t *in_pos, size_t in_size);
struct lzma_index_hash {};
lzma_index_hash * lzma_index_hash_init(
	lzma_index_hash *index_hash, lzma_allocator *allocator);
void lzma_index_hash_end(
	lzma_index_hash *index_hash, lzma_allocator *allocator);
lzma_ret lzma_index_hash_append(lzma_index_hash *index_hash,
                                lzma_vli unpadded_size, lzma_vli uncompressed_size);
lzma_ret lzma_index_hash_decode(lzma_index_hash *index_hash,
                                const ubyte *in_, size_t *in_pos, size_t in_size);
pure lzma_vli lzma_index_hash_size(
	const lzma_index_hash *index_hash);
enum LZMA_STREAM_HEADER_SIZE = 12;
struct lzma_stream_flags
{
	
	uint version_;
	
	lzma_vli backward_size;
	enum LZMA_BACKWARD_SIZE_MIN = 4;
	enum LZMA_BACKWARD_SIZE_MAX = (1UL << 34);
	
	lzma_check check;
	
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	lzma_reserved_enum reserved_enum4;
	lzma_bool reserved_bool1;
	lzma_bool reserved_bool2;
	lzma_bool reserved_bool3;
	lzma_bool reserved_bool4;
	lzma_bool reserved_bool5;
	lzma_bool reserved_bool6;
	lzma_bool reserved_bool7;
	lzma_bool reserved_bool8;
	uint reserved_int1;
	uint reserved_int2;
}
lzma_ret lzma_stream_header_encode(
	const lzma_stream_flags *options, ubyte *out_);
lzma_ret lzma_stream_footer_encode(
	const lzma_stream_flags *options, ubyte *out_);
lzma_ret lzma_stream_header_decode(
	lzma_stream_flags *options, const ubyte *in_);
lzma_ret lzma_stream_footer_decode(
	lzma_stream_flags *options, const ubyte *in_);
pure lzma_ret lzma_stream_flags_compare(
	const lzma_stream_flags *a, const lzma_stream_flags *b);

enum LZMA_VERSION_MAJOR = 5;
enum LZMA_VERSION_MINOR = 0;
enum LZMA_VERSION_PATCH = 3;
enum LZMA_VERSION_STABILITY = LZMA_VERSION_STABILITY_STABLE;
enum LZMA_VERSION_COMMIT = "";
enum LZMA_VERSION_STABILITY_ALPHA = 0;
enum LZMA_VERSION_STABILITY_BETA = 1;
enum LZMA_VERSION_STABILITY_STABLE = 2;
enum LZMA_VERSION = (LZMA_VERSION_MAJOR * 10000000U 
                     + LZMA_VERSION_MINOR * 10000U
                     + LZMA_VERSION_PATCH * 10U
                     + LZMA_VERSION_STABILITY);
static if (LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_ALPHA)
	enum LZMA_VERSION_STABILITY_STRING = "alpha";
else static if (LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_BETA)
	enum LZMA_VERSION_STABILITY_STRING = "beta";
else static if (LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_STABLE)
	enum LZMA_VERSION_STABILITY_STRING = "";
else
	static assert(false, "Incorrect LZMA_VERSION_STABILITY");
enum LZMA_VERSION_STRING = 
	to!string(LZMA_VERSION_MAJOR) ~ "." ~ to!string(LZMA_VERSION_MINOR) ~
		"." ~ to!string(LZMA_VERSION_PATCH) ~ LZMA_VERSION_STABILITY_STRING ~
		LZMA_VERSION_COMMIT;
uint lzma_version_number();
immutable(char)* lzma_version_string();
enum LZMA_VLI_MAX = (ulong.max / 2);
enum LZMA_VLI_UNKNOWN = ulong.max;
enum LZMA_VLI_BYTES_MAX = 9;
//#define LZMA_VLI_C(n) UINT64_C(n)
alias ulong lzma_vli;
bool lzma_vli_is_valid(lzma_vli vli)
{
	return vli <= LZMA_VLI_MAX || (vli) == LZMA_VLI_UNKNOWN;
}
lzma_ret lzma_vli_encode(lzma_vli vli, size_t *vli_pos,
                         ubyte* out_, size_t *out_pos, size_t out_size);
lzma_ret lzma_vli_decode(lzma_vli *vli, size_t *vli_pos,
                         const(ubyte)* in_, size_t *in_pos, size_t in_size);
pure uint lzma_vli_size(lzma_vli vli);

