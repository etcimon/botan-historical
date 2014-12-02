/*
* Zlib Compressor
* (C) 2001 Peter J Jones
*      2001-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.zlib;

import botan.filters.filter;
import botan.utils.exceptn;

import std.c.string;
import std.c.stdio;
import botan.utils.containers.hashmap;
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
        m_zlib.m_stream.next_in = cast(ubyte*)input;
        m_zlib.m_stream.avail_in = length;
        
        while (m_zlib.m_stream.avail_in != 0)
        {
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            m_zlib.m_stream.avail_out = m_buffer.length;
            deflate(&(m_zlib.m_stream), Z_NO_FLUSH);
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
        }
    }

    /*
    * Start Compressing with Zlib
    */
    void start_msg()
    {
        clear();
        m_zlib = new Zlib_Stream;
        
        int res = deflateInit2(&(m_zlib.m_stream),
                               m_level,
                               Z_DEFLATED,
                               (m_raw_deflate ? -15 : 15),
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
        m_zlib.m_stream.next_in = 0;
        m_zlib.m_stream.avail_in = 0;
        
        int rc = Z_OK;
        while (rc != Z_STREAM_END)
        {
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            m_zlib.m_stream.avail_out = m_buffer.length;
            
            rc = deflate(&(m_zlib.m_stream), Z_FINISH);
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
        }
        
        clear();
    }

    /**
    * Flush the compressor
    */
    void finished()
    {
        m_zlib.m_stream.next_in = 0;
        m_zlib.m_stream.avail_in = 0;
        
        while (true)
        {
            m_zlib.m_stream.avail_out = m_buffer.length;
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            
            deflate(&(m_zlib.m_stream), Z_FULL_FLUSH);
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
            
            if (m_zlib.m_stream.avail_out == m_buffer.length)
                break;
        }
    }

    /**
    * @param level = how much effort to use on compressing (0 to 9);
    *          higher levels are slower but tend to give better
    *          compression
    * @param raw_deflate = if true no m_zlib header/trailer will be used
    */
    this(size_t level = 6, bool raw_deflate = false)
    {
        
        m_level = (level >= 9) ? 9 : level;
        m_raw_deflate = raw_deflate;
        m_buffer = DEFAULT_BUFFERSIZE;
        m_zlib = 0;
    }

    ~this() { clear(); }
private:
    /*
    * Clean up Compression Context
    */
    void clear()
    {
        zeroise(m_buffer);
        
        if (m_zlib)
        {
            deflateEnd(&(m_zlib.m_stream));
            delete m_zlib;
            m_zlib = 0;
        }
    }

    const size_t m_level;
    const bool m_raw_deflate;

    Secure_Vector!ubyte m_buffer;
    Zlib_Stream m_zlib;
}

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
        if (length) m_no_writes = false;
        
        // non-const needed by m_zlib api :(
        ubyte* input = cast(ubyte*)(input_arr);
        
        m_zlib.m_stream.next_in = input;
        m_zlib.m_stream.avail_in = length;
        
        while (m_zlib.m_stream.avail_in != 0)
        {
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            m_zlib.m_stream.avail_out = m_buffer.length;
            
            int rc = inflate(&(m_zlib.m_stream), Z_SYNC_FLUSH);
            
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
            
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
            
            if (rc == Z_STREAM_END)
            {
                size_t read_from_block = length - m_zlib.m_stream.avail_in;
                start_msg();
                
                m_zlib.m_stream.next_in = input + read_from_block;
                m_zlib.m_stream.avail_in = length - read_from_block;
                
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
        m_zlib = new Zlib_Stream;
        
        if (inflateInit2(&(m_zlib.m_stream), (m_raw_deflate ? -15 : 15)) != Z_OK)
            throw new Memory_Exhaustion();
    }

    /*
    * Finish Decompressing with Zlib
    */
    void end_msg()
    {
        if (m_no_writes) return;
        m_zlib.m_stream.next_in = 0;
        m_zlib.m_stream.avail_in = 0;
        
        int rc = Z_OK;
        
        while (rc != Z_STREAM_END)
        {
            m_zlib.m_stream.next_out = cast(ubyte*)(m_buffer.ptr);
            m_zlib.m_stream.avail_out = m_buffer.length;
            rc = inflate(&(m_zlib.m_stream), Z_SYNC_FLUSH);
            
            if (rc != Z_OK && rc != Z_STREAM_END)
            {
                clear();
                throw new Decoding_Error("Zlib_Decompression: Error finalizing");
            }
            
            send(m_buffer.ptr, m_buffer.length - m_zlib.m_stream.avail_out);
        }
        
        clear();
    }


    /*
    * Zlib_Decompression Constructor
    */
    this(bool _raw_deflate = false)
    {
        m_raw_deflate = _raw_deflate;
        m_buffer = DEFAULT_BUFFERSIZE;
        m_zlib = null;
        m_no_writes = true;
    }

    ~this() { clear(); }
private:

    /*
    * Clean up Decompression Context
    */
    void clear()
    {
        zeroise(m_buffer);
        
        m_no_writes = true;
        
        if (m_zlib)
        {
            inflateEnd(&(m_zlib.m_stream));
            delete m_zlib;
            m_zlib = null;
        }
    }

    const bool m_raw_deflate;

    Secure_Vector!ubyte m_buffer;
    Zlib_Stream m_zlib;
    bool m_no_writes;
}


/*
* Allocation Information for Zlib
*/
class Zlib_Alloc_Info
{
public:
    HashMap!(void*, size_t) current_allocs;
}

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
    * Underlying m_stream
    */
    z_stream* m_stream;
    
    /**
    * Constructor
    */
    this()
    {
        memset(&m_stream, 0, (z_stream).sizeof);
        m_stream.zalloc = zlib_malloc;
        m_stream.zfree = zlib_free;
        m_stream.opaque = new Zlib_Alloc_Info;
    }
    
    /**
    * Destructor
    */
    ~this()
    {
        Zlib_Alloc_Info* info = cast(Zlib_Alloc_Info*)(m_stream.opaque);
        delete info;
        memset(m_stream, 0, (z_stream).sizeof);
    }
}