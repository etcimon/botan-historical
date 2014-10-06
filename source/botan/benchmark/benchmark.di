/*
* Runtime benchmarking
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.algo_factory;
import botan.rng;
import map;
import string;
import std.datetime;
/**
* Time aspects of an algorithm/provider
* @param name the name of the algorithm to test
* @param af the algorithm factory used to create objects
* @param provider the provider to use
* @param rng the rng to use to generate random inputs
* @param runtime total time for the benchmark to run
* @param buf_size size of buffer to benchmark against, in KiB
* @return results a map from op type to operations per second
*/
HashMap!(string, double)
time_algorithm_ops(in string name,
									  ref Algorithm_Factory af,
									  in string provider,
									  RandomNumberGenerator rng,
									  std::chrono::nanoseconds runtime,
									  size_t buf_size);

/**
* Algorithm benchmark
* @param name the name of the algorithm to test (cipher, hash, or MAC)
* @param af the algorithm factory used to create objects
* @param rng the rng to use to generate random inputs
* @param milliseconds total time for the benchmark to run
* @param buf_size size of buffer to benchmark against, in KiB
* @return results a map from provider to speed in mebibytes per second
*/
HashMap!(string, double)
algorithm_benchmark(in string name,
										ref Algorithm_Factory af,
										RandomNumberGenerator rng,
										std::chrono::milliseconds milliseconds,
										size_t buf_size);

double
time_op(std::chrono::nanoseconds runtime, std::function<void ()> op);