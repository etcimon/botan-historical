/*
* Pipe I/O for Unix
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/pipe.h>
/**
* Stream output operator; dumps the results from pipe's default
* message to the output stream.
* @param out file descriptor for an open output stream
* @param pipe the pipe
*/
int operator<<(int out, Pipe& pipe);

/**
* File descriptor input operator; dumps the remaining bytes of input
* to the (assumed open) pipe message.
* @param in file descriptor for an open input stream
* @param pipe the pipe
*/
int operator>>(int in, Pipe& pipe);