/*
* Startup Self Test
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.algo_factory;
import botan.scan_name;
import map;
import string;
/**
* Run a set of self tests on some basic algorithms like AES and SHA-1
* @param af an algorithm factory
* @throws Self_Test_Error if a failure occured
*/
void confirm_startup_self_tests(Algorithm_Factory& af);

/**
* Run a set of self tests on some basic algorithms like AES and SHA-1
* @param af an algorithm factory
* @returns false if a failure occured, otherwise true
*/
bool passes_self_tests(Algorithm_Factory& af);

/**
* Run a set of algorithm KATs (known answer tests)
* @param algo_name the algorithm we are testing
* @param vars a set of input variables for this test, all
			hex encoded. Keys used: "input", "output", "key", and "iv"
* @param af an algorithm factory
* @returns map from provider name to test result for that provider
*/
std::map<string, bool>
algorithm_kat(in SCAN_Name algo_name,
				  const HashMap!(string, string)& vars,
				  Algorithm_Factory& af);

/**
* Run a set of algorithm KATs (known answer tests)
* @param algo_name the algorithm we are testing
* @param vars a set of input variables for this test, all
			hex encoded. Keys used: "input", "output", "key", and "iv"
* @param af an algorithm factory
* @returns map from provider name to test result for that provider
*/
HashMap!(string, string)
algorithm_kat_detailed(in SCAN_Name algo_name,
							  const HashMap!(string, string)& vars,
							  Algorithm_Factory& af);