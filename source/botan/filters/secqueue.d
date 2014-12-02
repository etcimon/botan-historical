/*
* Secure_Queue
* (C) 1999-2007 Jack Lloyd
*      2012 Markus Wanner
*
* Distributed under the terms of the botan license.
*/
module botan.filters.secqueue;

import botan.filters.data_src;
import botan.filters.filter;
import botan.utils.types;
import std.algorithm;
/**
* A queue that knows how to zeroize itself
*/
final class Secure_Queue : Fanout_Filter, DataSource
{
public:
    @property string name() const { return "Queue"; }

    /*
    * Add some bytes to the queue
    */
    void write(in ubyte* input, size_t length)
    {
        if (!m_head)
            m_head = m_tail = new SecureQueueNode;
        while (length)
        {
            const size_t n = m_tail.write(input, length);
            input += n;
            length -= n;
            if (length)
            {
                m_tail.next = new SecureQueueNode;
                m_tail = m_tail.next;
            }
        }
    }

    /*
    * Read some bytes from the queue
    */
    size_t read(ubyte* output, size_t length)
    {
        size_t got = 0;
        while (length && m_head)
        {
            const size_t n = m_head.read(output, length);
            output += n;
            got += n;
            length -= n;
            if (m_head.length == 0)
            {
                SecureQueueNode holder = m_head.next;
                delete m_head;
                m_head = holder;
            }
        }
        bytes_read += got;
        return got;
    }

    /*
    * Read data, but do not remove it from queue
    */
    size_t peek(ubyte* output, size_t length, size_t offset = 0) const
    {
        SecureQueueNode current = m_head;
        
        while (offset && current)
        {
            if (offset >= current.length)
            {
                offset -= current.length;
                current = current.next;
            }
            else
                break;
        }
        
        size_t got = 0;
        while (length && current)
        {
            const size_t n = current.peek(output, length, offset);
            offset = 0;
            output += n;
            got += n;
            length -= n;
            current = current.next;
        }
        return got;
    }

    /**
    * Return how many bytes have been read so far.
    */
    size_t get_bytes_read() const
    {
        return bytes_read;
    }

    /*
    * Test if the queue has any data in it
    */
    bool end_of_data() const
    {
        return (size() == 0);
    }


    @property bool empty() const
    {
        return (size() == 0);
    }

    /**
    * @return number of bytes available in the queue
    */
    size_t size() const
    {
        SecureQueueNode current = m_head;
        size_t count = 0;
        
        while (current)
        {
            count += current.length;
            current = current.next;
        }
        return count;
    }

    bool attachable() { return false; }

    /**
    * Secure_Queue assignment
    * @param other = the queue to copy
    */
    Secure_Queue opAssign(in Secure_Queue input)
    {
        destroy();
        m_head = m_tail = new SecureQueueNode;
        SecureQueueNode temp = input.m_head;
        while (temp)
        {
            write(&temp.buffer[temp.m_start], temp.m_end - temp.m_start);
            temp = temp.m_next;
        }
        return this;
    }


    /**
    * Secure_Queue default constructor (creates empty queue)
    */
    this()
    {
        bytes_read = 0;
        set_next(null, 0);
        m_head = m_tail = new SecureQueueNode;
    }

    /**
    * Secure_Queue copy constructor
    * @param other = the queue to copy
    */
    this(in Secure_Queue input)
    {
        bytes_read = 0;
        set_next(null, 0);
        
        m_head = m_tail = new SecureQueueNode;
        SecureQueueNode temp = input.m_head;
        while (temp)
        {
            write(&temp.buffer[temp.m_start], temp.m_end - temp.m_start);
            temp = temp.next;
        }
    }

    ~this() { destroy(); }
private:
    size_t bytes_read;

    /*
    * Destroy this Secure_Queue
    */
    void destroy()
    {
        SecureQueueNode temp = m_head;
        while (temp)
        {
            SecureQueueNode holder = temp.m_next;
            delete temp;
            temp = holder;
        }
        m_head = m_tail = null;
    }

    SecureQueueNode m_head;
    SecureQueueNode m_tail;
}

/**
* A node in a Secure_Queue
*/
class SecureQueueNode
{
public:

    this() 
    { 
        m_buffer = DEFAULT_BUFFERSIZE; 
        m_next = null; 
        m_start = m_end = 0; }
    
    ~this() { 
        m_next = null; 
        m_start = m_end = 0; 
    }

    size_t write(in ubyte* input, size_t length)
    {
        size_t copied = std.algorithm.min(length, m_buffer.length - m_end);
        copy_mem(&m_buffer[end], input, copied);
        m_end += copied;
        return copied;
    }
    
    size_t read(ubyte* output, size_t length)
    {
        size_t copied = std.algorithm.min(length, m_end - m_start);
        copy_mem(output, &m_buffer[m_start], copied);
        m_start += copied;
        return copied;
    }
    
    size_t peek(ubyte* output, size_t length, size_t offset = 0)
    {
        const size_t left = m_end - m_start;
        if (offset >= left) return 0;
        size_t copied = std.algorithm.min(length, left - offset);
        copy_mem(output, &m_buffer[m_start + offset], copied);
        return copied;
    }
    
    size_t size() const { return (m_end - m_start); }
private:
    SecureQueueNode m_next;
    Secure_Vector!ubyte m_buffer;
    size_t m_start, m_end;
}