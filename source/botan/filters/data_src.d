/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*      2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/
module botan.filters.data_src;

import botan.constants;
import memutils.vector;
import botan.utils.types;
import std.stdio;
import botan.utils.exceptn;
import botan.utils.mem_ops;
import std.algorithm;

alias DataSource = RefCounted!DataSourceImpl;
alias DataSourceMemory = RefCounted!DataSourceMemoryImpl;
alias DataSourceStream = RefCounted!DataSourceStreamImpl;

/**
* This class represents an abstract data source object.
*/
interface DataSourceImpl
{
public:
    /**
    * Read from the source. Moves the internal offset so that every
    * call to read will return a new portion of the source.
    *
    * @param output = the ubyte array to write the result to
    * @param length = the length of the ubyte array out
    * @return length in bytes that was actually read and put
    * into out
    */
    size_t read(ubyte* output, size_t length);

    /**
    * Read from the source but do not modify the internal
    * offset. Consecutive calls to peek() will return portions of
    * the source starting at the same position.
    *
    * @param output = the ubyte array to write the output to
    * @param length = the length of the ubyte array out
    * @param peek_offset = the offset into the stream to read at
    * @return length in bytes that was actually read and put
    * into out
    */
    size_t peek(ubyte* output, size_t length, size_t peek_offset) const;

    /**
    * Test whether the source still has data that can be read.
    * @return true if there is still data to read, false otherwise
    */
    bool endOfData() const;
    /**
    * return the id of this data source
    * @return string representing the id of this data source
    */
    string id() const;

    /**
    * Read one ubyte.
    * @param output = the ubyte to read to
    * @return length in bytes that was actually read and put
    * into out
    */
    final size_t readByte(ref ubyte output)
    {
        return read(&output, 1);
    }


    /**
    * Peek at one ubyte.
    * @param output = an output ubyte
    * @return length in bytes that was actually read and put
    * into out
    */
    final size_t peekByte(ref ubyte output) const
    {
        return peek(&output, 1, 0);
    }


    /**
    * Discard the next N bytes of the data
    * @param N = the number of bytes to discard
    * @return number of bytes actually discarded
    */
    final size_t discardNext(size_t n)
    {
        size_t discarded = 0;
        ubyte dummy;
        foreach (size_t j; 0 .. n)
            discarded += readByte(dummy);
        return discarded;
    }


    /**
    * @return number of bytes read so far.
    */
    size_t getBytesRead() const;

}


/**
* This class represents a Memory-Based DataSource
*/
class DataSourceMemoryImpl : DataSourceImpl
{
public:
    override size_t read(ubyte* output, size_t length)
    {
        if (m_offset == m_source.length) return 0;
        size_t got = std.algorithm.min(m_source.length - m_offset, length);
        copyMem(output, &m_source[m_offset], got);
        m_offset += got;
        return got;
    }

    /*
    * Peek into a memory buffer
    */
    override size_t peek(ubyte* output, size_t length, size_t peek_offset) const
    {
        const size_t bytes_left = m_source.length - m_offset;
        if (peek_offset >= bytes_left) return 0;
        
        size_t got = std.algorithm.min(bytes_left - peek_offset, length);
        copyMem(output, &m_source[m_offset + peek_offset], got);
        return got;
    }

    /*
    * Check if the memory buffer is empty
    */
    override bool endOfData() const
    {
        return (m_offset == m_source.length);
    }


    /**
    * Construct a memory source that reads from a string
    * @param input = the string to read from
    */
    this(in string input) 
    {
        m_source = SecureVector!ubyte((cast(const(ubyte)*)input.ptr)[0 .. input.length]);
        m_offset = 0;
    }


    /**
    * Construct a memory source that reads from a ubyte array
    * @param input = the ubyte array to read from
    * @param length = the length of the ubyte array
    */
    this(const(ubyte)* input, size_t length)
    {
        m_source = SecureVector!ubyte(input[0 .. length]);
        m_offset = 0; 
    }

    /**
    * Construct a memory source that reads from a referenced vector
    * @param input = the MemoryRegion to read from
    */
    this(T, ALLOC)(auto const ref RefCounted!(Vector!(T, ALLOC), ALLOC) input)
    {
        m_source = SecureVector!ubyte(input[]);
        m_offset = 0;
    }

    /**
    * Construct a memory source that reads from a vector
    * @param input = the MemoryRegion to read from
    */
    this(T, ALLOC)(auto const ref Vector!(T, ALLOC) input) {
        m_source = SecureVector!ubyte(input.ptr[0 .. input.length]);
        m_offset = 0;
    }

    /**
    * Construct a memory source that reads from a vector*
    * @param input = the MemoryRegion to read from
    */
    this(T, ALLOC)(const Vector!(T, ALLOC)* input) {
        m_source = SecureVector!ubyte(input.ptr[0 .. input.length]);
        m_offset = 0;
    }

    override size_t getBytesRead() const { return m_offset; }
    override string id() const { return ""; }
private:
    SecureVector!ubyte m_source;
    size_t m_offset;
}

/**
* This class represents a Stream-Based DataSource.
*/
class DataSourceStreamImpl : DataSourceImpl
{
public:
    /*
    * Read from a stream
    */
    override size_t read(ubyte* output, size_t length)
    {
        //logTrace("Read for ", cast(void*)this, " len: ", length, " offset ", m_total_read);
        ubyte[] data;
        try data = m_source.rawRead(output[0..length]);
        catch (Exception e)
            throw new StreamIOError("read: Source failure..." ~ e.toString());
        
        size_t got = data.length;
        m_total_read += got;
        //logTrace("Read total: ", m_total_read, " end of stream? ", endOfData().to!string);
        return got;
    }

    /*
    * Peek into a stream
    */
    override size_t peek(ubyte* output, size_t length, size_t offset) const
    {
        //logTrace("Peek for ", cast(void*)this, " len: ", length, " offset ", offset, " total read ", m_total_read);
        File file;
        if (endOfData()) {
            file = File(m_identifier, "rb");
        }
           // throw new InvalidState("DataSourceStream: Cannot peek when out of data " ~ m_source.name);
        else file = cast(File)m_source;
        size_t got = 0;
        
        file.seek(offset, SEEK_SET);
        ubyte[] data;
        ubyte[] output_buf = output[0 .. length];
        try data = file.rawRead(output_buf);
        catch (Exception e)
            throw new StreamIOError("peek: Source failure..." ~ e.toString());
        
        got = data.length;
        //logTrace("Read total: ", got, " data: ", data);
        if (!file.isOpen) {
            file = File(m_identifier, "r");
        }
        else
        if (file.eof || file.error()) {
            file.clearerr();
            file.rewind();
        }
        
        file.seek(m_total_read, SEEK_SET);
        return got;
    }

    /*
    * Check if the stream is empty or in error
    */
    override bool endOfData() const
    {
        return !m_source.isOpen || m_source.eof || m_source.error();
    }

    /*
    * Return a human-readable ID for this stream
    */
    override string id() const
    {
        return m_identifier;
    }

    /*
    * DataSourceStream Constructor
    */
    this(ref File input, in string name)
    {
        m_identifier = name;
        m_source = input;
        m_total_read = 0;
    }

    /**
    * Construct a Stream-Based DataSource from file
    * @param file = the name of the file
    * @param use_binary = whether to treat the file as binary or not
    */
    this(in string path, bool use_binary = false)
    {
        
        m_identifier = path;
        m_source = File(path, use_binary ? "rb" : "r");
        m_source.open(path);
        m_total_read = 0;
        if (m_source.error())
        {
            throw new StreamIOError("DataSource: Failure opening file " ~ path);
        }
    }

    /*
    * DataSourceStream Destructor
    */
    ~this()
    {

    }

    override size_t getBytesRead() const { return m_total_read; }
private:
    const string m_identifier;

    File m_source;
    size_t m_total_read;
}