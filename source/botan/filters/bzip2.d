/*
* Bzip Compressor
* (C) 2001 Peter J Jones
*      2001-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.bzip2;
import botan.filters.filter;
import botan.utils.exceptn;

import botan.utils.containers.hashmap;
import std.c.string;
import std.c.stdlib;

/**
* Bzip Compression Filter
*/
final class Bzip_Compression : Filter
{
public:
    @property string name() const { return "Bzip_Compression"; }

    /*
    * Compress Input with Bzip
    */
    void write(in ubyte* input, size_t length)
    {
        m_bz.m_stream.next_in = cast(char*) input;
        m_bz.m_stream.avail_in = length;
        
        while (m_bz.m_stream.avail_in != 0)
        {
            m_bz.m_stream.next_out = cast(char*)(m_buffer.ptr);
            m_bz.m_stream.avail_out = m_buffer.length;
            BZ2_bzCompress(&(m_bz.m_stream), BZ_RUN);
            send(m_buffer, m_buffer.length - m_bz.m_stream.avail_out);
        }
    }
    /*
    * Start Compressing with Bzip
    */
    void startMsg()
    {
        clear();
        m_bz = new Bzip_Stream;
        if (BZ2_bzCompressInit(&(m_bz.m_stream), m_level, 0, 0) != BZ_OK)
            throw new Memory_Exhaustion();
    }

    /*
    * Finish Compressing with Bzip
    */
    void endMsg()
    {
        m_bz.m_stream.next_in = 0;
        m_bz.m_stream.avail_in = 0;
        
        int rc = BZ_OK;
        while (rc != BZ_STREAM_END)
        {
            m_bz.m_stream.next_out = cast(char*)(m_buffer.ptr);
            m_bz.m_stream.avail_out = m_buffer.length;
            rc = BZ2_bzCompress(&(m_bz.m_stream), BZ_FINISH);
            send(m_buffer, m_buffer.length - m_bz.m_stream.avail_out);
        }
        clear();
    }

    /*
    * Flush the Bzip Compressor
    */
    void finished()
    {
        m_bz.m_stream.next_in = 0;
        m_bz.m_stream.avail_in = 0;
        
        int rc = BZ_OK;
        while (rc != BZ_RUN_OK)
        {
            m_bz.m_stream.next_out = cast(char*)(m_buffer.ptr);
            m_bz.m_stream.avail_out = m_buffer.length;
            rc = BZ2_bzCompress(&(m_bz.m_stream), BZ_FLUSH);
            send(m_buffer, m_buffer.length - m_bz.m_stream.avail_out);
        }
    }

    this(size_t = 9)
    {
        m_level = (l >= 9) ? 9 : l;
        m_buffer = DEFAULT_BUFFERSIZE;
        m_bz = null;
    }
    ~this() { clear(); }
private:
    /*
    * Clean up Compression Context
    */
    void clear()
    {
        zeroise(m_buffer);
        
        if (m_bz)
        {
            BZ2_bzCompressEnd(&(m_bz.m_stream));
            delete m_bz;
            m_bz = null;
        }
    }

    const size_t m_level;
    SecureVector!ubyte m_buffer;
    Bzip_Stream m_bz;
}

/**
* Bzip Decompression Filter
*/
final class Bzip_Decompression : Filter
{
public:
    @property string name() const { return "Bzip_Decompression"; }

    /*
    * Decompress Input with Bzip
    */
    void write(in ubyte* input_arr, size_t length)
    {
        if (length) m_no_writes = false;
        
        char* input = cast(char*) input_arr;
        
        m_bz.m_stream.next_in = input;
        m_bz.m_stream.avail_in = length;
        
        while (m_bz.m_stream.avail_in != 0)
        {
            m_bz.m_stream.next_out = cast(char*)(m_buffer.ptr);
            m_bz.m_stream.avail_out = m_buffer.length;
            
            int rc = BZ2_bzDecompress(&(m_bz.m_stream));
            
            if (rc != BZ_OK && rc != BZ_STREAM_END)
            {
                clear();
                
                if (rc == BZ_DATA_ERROR)
                    throw new Decoding_Error("Bzip_Decompression: Data integrity error");
                else if (rc == BZ_DATA_ERROR_MAGIC)
                    throw new Decoding_Error("Bzip_Decompression: Invalid input");
                else if (rc == BZ_MEM_ERROR)
                    throw new Memory_Exhaustion();
                else
                    throw new Exception("Bzip2 decompression: Unknown error");
            }
            
            send(m_buffer, m_buffer.length - m_bz.m_stream.avail_out);
            
            if (rc == BZ_STREAM_END)
            {
                size_t read_from_block = length - m_bz.m_stream.avail_in;
                startMsg();
                m_bz.m_stream.next_in = input + read_from_block;
                m_bz.m_stream.avail_in = length - read_from_block;
                input += read_from_block;
                length -= read_from_block;
            }
        }
    }

    /*
    * Start Decompressing with Bzip
    */
    void startMsg()
    {
        clear();
        m_bz = new Bzip_Stream;
        
        if (BZ2_bzDecompressInit(&(m_bz.m_stream), 0, m_small_mem) != BZ_OK)
            throw new Memory_Exhaustion();
        
        m_no_writes = true;
    }

    /*
    * Finish Decompressing with Bzip
    */
    void endMsg()
    {
        if (m_no_writes) return;
        m_bz.m_stream.next_in = 0;
        m_bz.m_stream.avail_in = 0;
        
        int rc = BZ_OK;
        while (rc != BZ_STREAM_END)
        {
            m_bz.m_stream.next_out = cast(char*)(m_buffer.ptr);
            m_bz.m_stream.avail_out = m_buffer.length;
            rc = BZ2_bzDecompress(&(m_bz.m_stream));
            
            if (rc != BZ_OK && rc != BZ_STREAM_END)
            {
                clear();
                throw new Decoding_Error("Bzip_Decompression: Error finalizing");
            }
            
            send(m_buffer, m_buffer.length - bz.m_stream.avail_out);
        }
        
        clear();
    }

    this(bool small = false)
    {
        m_small_mem = small;
        m_buffer = DEFAULT_BUFFERSIZE;
        m_no_writes = true;
        m_bz = null;
    }
    ~this() { clear(); }
private:
    /*
    * Clean up Decompression Context
    */
    void clear()
    {
        zeroise(buffer);
        
        if (bz)
        {
            BZ2_bzDecompressEnd(&(m_bz.m_stream));
            delete m_bz;
            m_bz = null;
        }
    }

    const bool m_small_mem;
    SecureVector!ubyte m_buffer;
    Bzip_Stream m_bz;
    bool m_no_writes;
}

/*
* Allocation Information for Bzip
*/
final class Bzip_Alloc_Info
{
public:
    HashMap!(void*, size_t) current_allocs;
}


/**
* Wrapper Type for Bzip2 Stream
*/
final class Bzip_Stream
{
public:
    /**
    * Underlying m_stream
    */
    bz_stream* m_stream;

    /**
    * Constructor
    */
    this()
    {
        memset(&m_stream, 0, (bz_stream).sizeof);
        m_stream.bzalloc = bzip_malloc;
        m_stream.bzfree = bzip_free;
        m_stream.opaque = new Bzip_Alloc_Info;
    }
    
    /**
    * Destructor
    */
    ~this()
    {
        Bzip_Alloc_Info* info = cast(Bzip_Alloc_Info*)(m_stream.opaque);
        delete info;
        memset(m_stream, 0, (bz_stream).sizeof);
    }
}

/*
* Allocation Function for Bzip
*/
void* bzip_malloc(void* info_ptr, int n, int size)
{
    Bzip_Alloc_Info* info = cast(Bzip_Alloc_Info*)(info_ptr);
    
    const size_t total_sz = n * size;
    
    void* ptr = malloc(total_sz);
    info.current_allocs[ptr] = total_sz;
    return ptr;
}

/*
* Allocation Function for Bzip
*/
void bzip_free(void* info_ptr, void* ptr)
{
    Bzip_Alloc_Info* info = cast(Bzip_Alloc_Info*)(info_ptr);
    auto i = info.current_allocs.find(ptr);
    if (i == info.current_allocs.end())
        throw new Invalid_Argument("bzip_free: Got pointer not allocated by us");
    
    memset(ptr, 0, i.second);
    free(ptr);
}


/*-------------------------------------------------------------*/
/*--- Public header file for the library.                   ---*/
/*---                                               bzlib.h ---*/
/*-------------------------------------------------------------*/
/**
*   This file is part of bzip2/libbzip2, a program and library for
*   lossless, block-sorting data compression.
*   
*   bzip2/libbzip2 version 1.0.6 of 6 September 2010
*   Copyright (C) 1996-2010 Julian Seward <jseward@bzip.org>
*   
*   Please read the WARNING, DISCLAIMER and PATENTS sections in the 
*   README file.
*   
*   This program is released under the terms of the license contained
*   in the file LICENSE.
*/

extern(C) nothrow:

enum BZ_RUN               = 0;
enum BZ_FLUSH             = 1;
enum BZ_FINISH            = 2;

enum BZ_OK                = 0;
enum BZ_RUN_OK            = 1;
enum BZ_FLUSH_OK          = 2;
enum BZ_FINISH_OK         = 3;
enum BZ_STREAM_END        = 4;
enum BZ_SEQUENCE_ERROR    = -1;
enum BZ_PARAM_ERROR       = -2;
enum BZ_MEM_ERROR         = -3;
enum BZ_DATA_ERROR        = -4;
enum BZ_DATA_ERROR_MAGIC  = -5;
enum BZ_IO_ERROR          = -6;
enum BZ_UNEXPECTED_EOF    = -7;
enum BZ_OUTBUFF_FULL      = -8;
enum BZ_CONFIG_ERROR      = -9;


struct bz_stream
{
    ubyte* next_in;
    uint   avail_in;
    uint   total_in_lo32;
    uint   total_in_hi32;
    
    ubyte* next_out;
    uint   avail_out;
    uint   total_out_lo32;
    uint   total_out_hi32;
    
    void*  state;
    
    void* function(void*, int, int) nothrow bzalloc;
    void  function(void*, void*) nothrow    bzfree;
    void* opaque;
} 

/*-- Core (low-level) library functions --*/

int BZ2_bzCompressInit( 
                       bz_stream* strm, 
                       int        blockSize100k, 
                       int        verbosity, 
                       int        workFactor 
                       );

int BZ2_bzCompress( 
                   bz_stream* strm, 
                   int action 
                   );

int BZ2_bzCompressEnd( 
                      bz_stream* strm 
                      );

int BZ2_bzDecompressInit( 
                         bz_stream* strm, 
                         int        verbosity, 
                         int        small
                         );

int BZ2_bzDecompress( 
                     bz_stream* strm 
                     );

int BZ2_bzDecompressEnd( 
                        bz_stream *strm 
                        );

/*--
   Code contributed by Yoshioka Tsuneo (tsuneo@rr.iij4u.or.jp)
   to support better zlib compatibility.
   This code is not _officially_ part of libbzip2 (yet);
   I haven't tested it, documented it, or considered the
   threading-safeness of it.
   If this code breaks, please contact both Yoshioka and me.
--*/

const(char)* BZ2_bzlibVersion();

/*-------------------------------------------------------------*/
/*--- end                                           bzlib.h ---*/
/*-------------------------------------------------------------*/