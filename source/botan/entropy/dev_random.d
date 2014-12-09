/*
* /dev/random EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.dev_random;

version(Posix):
import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM):

import botan.entropy.entropy_src;
import botan.utils.types;
// import string;
import core.sys.posix.sys.types;
import core.sys.posix.sys.select;
import core.sys.posix.sys.stat;
import core.sys.posix.unistd;
import core.sys.posix.fcntl;
import std.c.string;
import botan.utils.rounding;

/**
* Entropy source reading from kernel devices like /dev/random
*/
final class DeviceEntropySource : EntropySource
{
public:
    @property string name() const { return "RNG Device Reader"; }

    /**
    * Gather entropy from a RNG device
    */
    void poll(ref EntropyAccumulator accum)
    {
        if (m_devices.empty)
            return;
        
        __gshared immutable size_t ENTROPY_BITS_PER_BYTE = 8;
        __gshared immutable size_t MS_WAIT_TIME = 32;
        __gshared immutable size_t READ_ATTEMPT = 32;
        
        int max_fd = m_devices[0];
        fd_set read_set;
        FD_ZERO(&read_set);
        foreach (device; m_devices[])
        {
            FD_SET(device, &read_set);
            max_fd = std.algorithm.max(device, max_fd);
        }
        
        timeval timeout;
        
        timeout.tv_sec = (MS_WAIT_TIME / 1000);
        timeout.tv_usec = (MS_WAIT_TIME % 1000) * 1000;
        
        if (select(max_fd + 1, &read_set, null, null, &timeout) < 0)
            return;
        
        SecureVector!ubyte io_buffer = accum.getIoBuffer(READ_ATTEMPT);

        foreach (device; m_devices[])
        {
            if (FD_ISSET(device, &read_set))
            {
                const ssize_t got = read(device, io_buffer.ptr, io_buffer.length);
                if (got > 0)
                    accum.add(io_buffer.ptr, got, ENTROPY_BITS_PER_BYTE);
            }
        }
    }


    /**
    Device_EntropySource constructor
    Open a file descriptor to each (available) device in fsnames
    */
    this(in Vector!string fsnames)
    {
        enum O_NONBLOCK = 0;
        enum O_NOCTTY = 0;
        
        const int flags = O_RDONLY | O_NONBLOCK | O_NOCTTY;
        
        foreach (fsname; fsnames[])
        {
            FDType fd = open(fsname.toStringz, flags);
            
            if (fd >= 0 && fd < FD_SETSIZE)
                m_devices.pushBack(fd);
            else if (fd >= 0)
                close(fd);
        }
    }

    ~this()
    {
        foreach (device; m_devices[])
            close(device);
    }
private:
	alias FDType = int;

    Vector!FDType m_devices;
}