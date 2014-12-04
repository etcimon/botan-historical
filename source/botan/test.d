module botan.test;

import botan.constants;

// static if (BOTAN_TEST):

public import std.stdio : File, writeln, dirEntries;
public import std.algorithm : sort, canFind;
public import std.string : indexOf, lastIndexOf;
public import botan.utils.types;
public import botan.libstate.libstate;
import std.file;
import std.exception;

string CHECK_MESSAGE (bool expr, string print) {
    return `
    {
        try { 
            if (!(expr)) { 
                ++fails; 
                writeln( q{ ` ~ print ~ ` } ); 
            } 
        } 
        catch(Exception e) 
        { 
            writeln(__FUNCTION__, " : " ~ e.msg); 
        }
    }`;
}

string CHECK (string expr) {
    return `
    {
        mixin( q{
            bool sucess = ` ~ expr ~ `;
        } );
        try { 
            if (!success)
            { ++fails; writeln( q { ` ~ expr ~ ` } ); } 
        } 
        catch(Exception e) 
        { 
            writeln(__FUNCTION__ ~ " : " ~ e.msg); 
        }
    }`;
}


Vector!string listDir(string dir_path)
{
    Vector!string paths;
    
    foreach (file; dirEntries(dir_path, "*.vec").sort!`a.name < b.name`())
    {    
        paths.pushBack(file.name);
    }
    
    return paths;
}

size_t runTestsInDir(string dir, size_t delegate(string) fn)
{
    import std.parallelism;
    import core.atomic;
    shared(size_t) shared_fails;
    
    foreach (vec; parallel(listDir(dir))) {
        size_t local_fails = fn(vec);
        atomicOp!"+="(shared_fails, local_fails);
    }
    
    return shared_fails;
}

void testReport(string name, size_t ran, size_t failed)
{
    writeln(name);
    
    if(ran > 0)
        writeln(" " ~ ran ~ " tests");
    
    if(failed)
        writeln(" " ~ failed ~ " FAILs");
    else
        writeln(" all ok");
}

size_t runTestsBb(ref File src,
                    string name_key,
                    string output_key,
                    bool clear_between_cb,
                    size_t delegate(string[string]) cb)
{
    if(src.eof || src.error)
    {
        writeln("Could not open input file for " ~ name_key);
        return 1;
    }
    
    string[string] vars;
    size_t test_fails = 0, algo_fail = 0;
    size_t test_count = 0, algo_count = 0;
    
    string fixed_name;
    
    string line;
    while(!src.eof && !src.error)
    {
        line = src.readln();
        
        if(line == "")
            continue;
        
        if(line[0] == '#')
            continue;
        
        if(line[0] == '[' && line[$-1] == ']')
        {
            if(fixed_name != "")
                testReport(fixed_name, algo_count, algo_fail);
            
            test_count += algo_count;
            test_fails += algo_fail;
            algo_count = 0;
            algo_fail = 0;
            fixed_name = line[1 .. $ - 2];
            vars[name_key] = fixed_name;
            continue;
        }
        
        const string key = line[0 .. line.indexOf(' ')];
        const string val = line[line.lastIndexOf(' ') + 1 .. $];
        
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
        testReport(fixed_name, algo_count, algo_fail);
    else
        testReport(name_key, test_count, test_fails);
    
    return test_fails;
}

size_t runTests(string filename,
                 string name_key,
                 string output_key,
                 bool clear_between_cb,
                 string delegate(string[string]) cb)
{
    File vec = File(filename, "r");
    
    if(vec.error || vec.eof)
    {
        writeln("Failure opening " ~ filename);
        return 1;
    }
    
    return runTests(vec, name_key, output_key, clear_between_cb, cb);
}

size_t runTests(ref File src,
                 string name_key,
                 string output_key,
                 bool clear_between_cb,
                 string delegate(string[string]) cb)
{
    return runTestsBb(src, name_key, output_key, clear_between_cb, 
                        (string[string] vars)
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