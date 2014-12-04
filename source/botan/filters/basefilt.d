/*
* Basic Filters
* (C) 1999-2007 Jack Lloyd
* (C) 2013 Joel Low
*
* Distributed under the terms of the botan license.
*/
module botan.filters.basefilt;

import botan.filters.filter;
import std.concurrency;
import botan.utils.memory : FreeListRef;
import botan.filters.key_filt;

import botan.utils.semaphore;

/**
* BitBucket is a filter which simply discards all inputs
*/
final class BitBucket : Filter
{
    void write(in ubyte*, size_t) {}

    @property string name() const { return "BitBucket"; }
}

/**
* This class represents Filter chains. A Filter chain is an ordered
* concatenation of Filters, the input to a Chain sequentially passes
* through all the Filters contained in the Chain.
*/

final class Chain : FanoutFilter
{
public:
    void write(in ubyte* input, size_t length) { send(input, length); }

    @property string name() const
    {
        return "Chain";
    }

    /**
    * Construct a chain of up to four filters. The filters are set
    * up in the same order as the arguments.
    */
    this(Filter f1 = null, Filter f2 = null,
            Filter f3 = null, Filter f4 = null)
    {
        if (f1) { attach(f1); incr_owns(); }
        if (f2) { attach(f2); incr_owns(); }
        if (f3) { attach(f3); incr_owns(); }
        if (f4) { attach(f4); incr_owns(); }
    }

    /**
    * Construct a chain from range of filters
    * @param filter_arr = the list of filters
    * @param length = how many filters
    */
    this(Filter* filter_arr, size_t length) {
        foreach (size_t j; 0 .. length) {
            if (filter_arr[j])
            {
                attach(filter_arr[j]);
                incr_owns();
            }
        }
    }


}

/**
* This class represents a fork filter, whose purpose is to fork the
* flow of data. It causes an input message to result in n messages at
* the end of the filter, where n is the number of forks.
*/
class Fork : FanoutFilter
{
public:
    final void write(in ubyte* input, size_t length) { send(input, length); }
    final void setPort(size_t n) { super.setPort(n); }

    @property string name() const
    {
        return "Fork";
    }

    /**
    * Construct a Fork filter with up to four forks.
    */
    this(Filter f1, Filter f2, Filter f3 = null, Filter f4 = null)
    {
        Filter[4] filters = [ f1, f2, f3, f4 ];
        setNext(filters, 4);
    }

    /**
    * Construct a Fork from range of filters
    * @param filter_arr = the list of filters
    * @param length = how many filters
    */    
    this(Filter* filter_arr, size_t length)
    {
        setNext(filter_arr, length);
    }
}

/**
* This class is a threaded version of the Fork filter. While this uses
* threads, the class itself is NOT thread-safe. This is meant as a drop-
* in replacement for Fork where performance gains are possible.
*/
class ThreadedFork : Fork
{
public:
    @property string name() const
    {
        return "Threaded Fork";
    }

    /**
    * Construct a Threaded_Fork filter with up to four forks.
    */
    this(Filter f1, Filter f2, Filter f3 = null, Filter f4 = null)
    { 
        super(null, cast(size_t)(0));
        m_thread_data = new ThreadedForkData;
        Filter[4] filters = [ f1, f2, f3, f4 ];
        setNext(filters, 4);
    }

    /**
    * Construct a Threaded_Fork from range of filters
    * @param filter_arr = the list of filters
    * @param length = how many filters
    */
    this(Filter* filter_arr, size_t length)
    {
        
        super(null, cast(size_t)(0));
        m_thread_data = new ThreadedForkData;
        setNext(filter_arr, length);
    }

    ~this()
    {
        m_thread_data.m_input = null;
        m_thread_data.m_input_length = 0;
        
        m_thread_data.m_input_ready_semaphore.release(m_threads.length);
        
        foreach (ref thread; m_threads)
            thread.join();
    }

protected:
    void setNext(Filter* f, size_t n)
    {
        super.setNext(f, n);
        n = next.length;
        
        if (n < m_threads.length)
            m_threads.resize(n);
        else
        {
            m_threads.reserve(n);
            foreach (size_t i; m_threads.length .. n)
            {
                m_threads.pushBack(
                    FreeListRef!Thread(
                        spawn(&threadEntry, this, next[i])));
            }
        }
    }

    void send(in ubyte* input, size_t length)
    {
        if (m_write_queue.length)
            thread_delegate_work(m_write_queue.ptr, m_write_queue.length);
        thread_delegate_work(input, length);
        
        bool nothing_attached = true;
        foreach (size_t j; 0 .. total_ports())
            if (next[j])
                nothing_attached = false;
        
        if (nothing_attached)
            m_write_queue ~= input[0 .. length];
        else
            m_write_queue.clear();
    }

private:
    void threadDelegateWork(in ubyte* input, size_t length)
    {
        //Set the data to do.
        m_thread_data.m_input = input;
        m_thread_data.m_input_length = length;
        
        //Let the workers start processing.
        m_thread_data.m_input_ready_semaphore.release(total_ports());
        
        //Wait for all the filters to finish processing.
        foreach (size_t i; 0 .. total_ports())
            m_thread_data.m_input_complete_semaphore.acquire();
        
        //Reset the thread data
        m_thread_data.m_input = null;
        m_thread_data.m_input_length = 0;
    }

    static void threadEntry(ThreadedFork This, Filter filter)
    {
        while (true)
        {
            This.m_thread_data.m_input_ready_semaphore.acquire();
            
            if (!This.m_thread_data.m_input)
                break;
            
            filter.write(m_thread_data.m_input, m_thread_data.m_input_length);
            This.m_thread_data.m_input_complete_semaphore.release();
        }
    }

    Vector!(FreeListRef!Tid) m_threads;
    Unique!Threaded_Fork_Data m_thread_data;
}

struct ThreadedForkData
{
    /*
    * Semaphore for indicating that there is work to be done (or to
    * quit)
    */
    Semaphore m_input_ready_semaphore;
    
    /*
    * Ensures that all threads have completed processing data.
    */
    Semaphore m_input_complete_semaphore;
    
    /*
    * The work that needs to be done. This should be only when the threads
    * are NOT running (i.e. before notifying the work condition, after
    * the input_complete_semaphore is completely reset.)
    */
    const ubyte* m_input;
    
    /*
    * The length of the work that needs to be done.
    */
    size_t m_input_length = 0;
}