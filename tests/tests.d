#include "tests.h"
#include <botan/init.h>
#include <iostream>
#include <fstream>
#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

Vector!string list_dir(string dir_path)
{
	Vector!string paths;

	fs::recursive_directory_iterator dir(dir_path), end;

	while (dir != end)
	{	
		if(dir.path().extension().string() == ".vec")
			paths.push_back(dir.path().string());
		++dir;
	}

	std::sort(paths.begin(), paths.end());

	return paths;
}

size_t run_tests_in_dir(string dir, size_t delegate(string) fn)
{
	size_t fails = 0;
	for(auto vec: list_dir(dir))
		fails += fn(vec);
	return fails;
}

size_t run_tests(input Vector!test_fn tests)
{
	size_t fails = 0;

	for(auto test : tests)
	{
		try
		{
			fails += test();
		}
		catch(Exception e)
		{
			writeln("Exception escaped test: " ~ e.msg);
			++fails;
		}
		catch(...)
		{
			writeln("Exception escaped test");
			++fails;
		}
	}

	test_report("Tests", 0, fails);

	return fails;
}

void test_report(string name, size_t ran, size_t failed)
{
	writeln(name;

	if(ran > 0)
		writeln(" " ~ ran ~ " tests";

	if(failed)
		writeln(" " ~ failed ~ " FAILs");
	else
		writeln(" all ok");
}

size_t run_tests_bb(File src,
						  string name_key,
						  string output_key,
						  bool clear_between_cb,
						  size_t delegate(string[string]) cb)
{
	if(!src.good())
	{
		writeln("Could not open input file for " ~ name_key);
		return 1;
	}

	string[string] vars;
	size_t test_fails = 0, algo_fail = 0;
	size_t test_count = 0, algo_count = 0;

	string fixed_name;

	while(src.good())
	{
		string line;
		std::getline(src, line);

		if(line == "")
			continue;

		if(line[0] == '#')
			continue;

		if(line[0] == '[' && line[line.length-1] == ']')
		{
			if(fixed_name != "")
				test_report(fixed_name, algo_count, algo_fail);

			test_count += algo_count;
			test_fails += algo_fail;
			algo_count = 0;
			algo_fail = 0;
			fixed_name = line.substr(1, line.length - 2);
			vars[name_key] = fixed_name;
			continue;
		}

		const string key = line.substr(0, line.find_first_of(' '));
		const string val = line.substr(line.find_last_of(' ') + 1, -1);

		vars[key] = val;

		if(key == name_key)
			fixed_name.clear();

		if(key == output_key)
		{
			//writeln(vars[name_key] " ~ " ~ algo_count);
			++algo_count;
			try
			{
				const size_t fails = cb(vars);

				if(fails)
				{
					writeln(vars[name_key] ~ " test " ~ algo_count ~ " : " ~ fails ~ " failure");
					algo_fail += fails;
				}
			}
			catch(Exception e)
			{
				writeln(vars[name_key] ~ " test " ~ algo_count ~ " failed: " ~ e.msg);
				++algo_fail;
			}

			if(clear_between_cb)
			{
				vars.clear();
				vars[name_key] = fixed_name;
			}
		}
	}

	test_count += algo_count;
	test_fails += algo_fail;

	if(fixed_name != "" && (algo_count > 0 || algo_fail > 0))
		test_report(fixed_name, algo_count, algo_fail);
	else
		test_report(name_key, test_count, test_fails);

	return test_fails;
}

size_t run_tests(string filename,
					  string name_key,
					  string output_key,
					  bool clear_between_cb,
					  string delegate(string[string]) cb)
{
	File vec(filename);

	if(!vec)
	{
		writeln("Failure opening " ~ filename);
		return 1;
	}

	return run_tests(vec, name_key, output_key, clear_between_cb, cb);
}

size_t run_tests(File src,
					  string name_key,
					  string output_key,
					  bool clear_between_cb,
					  string delegate(string[string]) cb)
{
	return run_tests_bb(src, name_key, output_key, clear_between_cb,
					 [name_key,output_key,cb](string[string] vars)
					 {
					 const string got = cb(vars);
					 if(got != vars[output_key])
						 {
						 writeln(name_key ~ ' ' ~ vars[name_key] ~ " got " ~ got ~ " expected " ~ vars[output_key]);
						 return 1;
						 }
					 return 0;
					 });
}

namespace {

int help(char* argv0)
{
	writeln("Usage: " ~ argv0 ~ " [suite]");
	writeln("Suites: all (default), block, hash, bigint, rsa, ecdsa, ...");
	return 1;
}

}

int main(int argc, char* argv[])
{
	if(argc != 1 && argc != 2)
		return help(argv[0]);

	string target = "all";

	if(argc == 2)
		target = argv[1];

	if(target == "-h" || target == "--help" || target == "help")
		return help(argv[0]);

	std::vector<test_fn> tests;

#define DEF_TEST(test) do { if(target == "all" || target == #test) \
		tests.push_back(test_ ## test);										\
} while(0)

	DEF_TEST(block);
	DEF_TEST(modes);
	DEF_TEST(aead);
	DEF_TEST(ocb);

	DEF_TEST(stream);
	DEF_TEST(hash);
	DEF_TEST(mac);
	DEF_TEST(pbkdf);
	DEF_TEST(kdf);
	DEF_TEST(hkdf);
	DEF_TEST(keywrap);
	DEF_TEST(transform);
	DEF_TEST(rngs);
	DEF_TEST(passhash9);
	DEF_TEST(bcrypt);
	DEF_TEST(cryptobox);
	DEF_TEST(tss);
	DEF_TEST(rfc6979);

	DEF_TEST(bigint);

	DEF_TEST(rsa);
	DEF_TEST(rw);
	DEF_TEST(dsa);
	DEF_TEST(nr);
	DEF_TEST(dh);
	DEF_TEST(dlies);
	DEF_TEST(elgamal);
	DEF_TEST(ecdsa);
	DEF_TEST(gost_3410);

	DEF_TEST(ecc_unit);
	DEF_TEST(ecdsa_unit);
	DEF_TEST(ecdh_unit);
	DEF_TEST(pk_keygen);
	DEF_TEST(cvc);
	DEF_TEST(x509);
	DEF_TEST(nist_x509);
	DEF_TEST(tls);

	if(tests.empty())
	{
		writeln("No tests selected by target '" ~ target ~ "'");
		return 1;
	}

	LibraryInitializer init;

	return run_tests(tests);
}
