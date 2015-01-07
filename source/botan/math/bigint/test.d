module botan.math.bigint.test;

import botan.constants;
static if (BOTAN_TEST):

import botan.rng.rng;
import botan.rng.auto_rng;
import botan.utils.exceptn;
import botan.math.numbertheory.numthry;
import botan.test;

void stripComments(string line)
{
    if (line.canFind('#'))
        line = line[0 .. line.indexOf('#')];
}

/* Strip comments, whitespace, etc */
void strip(string line)
{
    stripComments(line);
    
    /*    while(line.canFind(' '))
        line = line[0 .. line.indexOf(' ')];
*/
    
    while(line.canFind('\t'))
        line = line[0 .. line.indexOf('\t')];
}

Vector!string parse(string line)
{
    import std.string : indexOf;
    const char DELIMITER = ':';
    Vector!string substr;
    size_t end = line.indexOf(DELIMITER);
    string line_ = line;
    while(end != -1)
    {
        substr.pushBack(line_[0 .. end]);
        if (end+1 >= line.length)
            break;
        line_ = line_[end+1 .. $];
        end = line_.indexOf(DELIMITER);
    }
    while(substr.length <= 4) // at least 5 substr, some possibly empty
        substr.pushBack("");
    return substr;
}

// c==expected, d==a op b, e==a op= b
size_t results(string op, in BigInt a, in BigInt b, in BigInt c, in BigInt d, in BigInt e)
{
    string op1 = "operator" ~ op;
    string op2 = op1 ~ "=";
    
    if (c == d && d == e)
        return 0;
    else
    {
        writeln();
        
        writeln("ERROR: " ~ op1);
        
        writeln("a = ", a);
        writeln("b = ", b);
        
        writeln("c = ", c);
        writeln("d = ", d);
        writeln("e = ", e);
        
        if (d != e)
        {
            writeln("ERROR: " ~ op1 ~ " | " ~ op2 ~ " mismatch");
        }
        return 1;
    }
}

size_t checkAdd(in Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a.dup + b;
    BigInt e = a.dup;
    e += b;
    
    if (results("+", a, b, c, d, e))
        return 1;
    
    d = b.dup + a;
    e = b.dup;
    e += a;
    
    return results("+", a, b, c, d, e);
}

size_t checkSub(in Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a.dup - b;
    BigInt e = a.dup;
    e -= b;
    
    return results("-", a, b, c, d, e);
}

size_t checkMul(in Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    /*
    writeln("a = " ~ args[0] " ~\n"
                 " ~b = " ~ args[1]);
    */
    /* This makes it more likely the fast multiply algorithms will be usable,
        which is what we really want to test here (the simple n^2 multiply is
        pretty well tested at this point).
    */
    a.growTo(64);
    b.growTo(64);
    
    BigInt d = a.dup * b;
    BigInt e = a.dup;
    e *= b;
    
    if (results("*", a, b, c, d, e))
        return 1;
    
    d = b.dup * a;
    e = b.dup;
    e *= a;
    
    return results("*", a, b, c, d, e);
}

size_t checkSqr(in Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    
    a.growTo(64);
    b.growTo(64);
    
    BigInt c = square(a);
    BigInt d = a.dup * a;
    
    return results("sqr", a, a, b, c, d);
}

size_t checkDiv(in Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a / b;
    BigInt e = a;
    e /= b;
    
    return results("/", a, b, c, d, e);
}

size_t checkMod(in Vector!string args, RandomNumberGenerator rng)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt c = BigInt(args[2]);
    
    BigInt d = a.dup % b;
    BigInt e = a.dup;
    e %= b;
    
    size_t got = results("%", a, b, c, d, e);
    
    if (got) return got;
    
    word b_word = b.wordAt(0);
    
    /* Won't work for us, just pick one at random */
    while(b_word == 0)
        for(size_t j = 0; j != 2*word.sizeof; j++)
            b_word = (b_word << 4) ^ rng.nextByte();
    
    b = b_word;
    
    c = a.dup % b; /* we declare the BigInt % BigInt version to be correct here */
    
    word d2 = a.dup % b_word;
    e = a.dup;
    e %= b_word;
    
    return results("%(word)", a, b, c, BigInt(d2), e);
}

size_t checkShl(in Vector!string args)
{
    BigInt a = BigInt(args[0]);
    size_t b = args[1].to!size_t;
    BigInt c = BigInt(args[2]);
    
    BigInt d = a.dup << b;
    BigInt e = a.dup;
    e <<= b;
    
    return results("<<", a, BigInt(b), c, d, e);
}

size_t checkShr(in Vector!string args)
{
    BigInt a = BigInt(args[0]);
    size_t b = args[1].to!size_t;
    BigInt c = BigInt(args[2]);
    
    BigInt d = a.dup >> b;
    BigInt e = a.dup;
    e >>= b;
    
    return results(">>", a, BigInt(b), c, d, e);
}

/* Make sure that (a^b)%m == r */
size_t checkPowmod(in Vector!string args)
{
    BigInt a = BigInt(args[0]);
    BigInt b = BigInt(args[1]);
    BigInt m = BigInt(args[2]);
    BigInt c = BigInt(args[3]);
    
    BigInt r = powerMod(a, b, m);
    
    if (c != r)
    {
        writeln("ERROR: powerMod");
        writeln("a = ", a);
        writeln("b = ", b);
        writeln("m = ", m);
        writeln("c = ", c);
        writeln("r = ", r);
        return 1;
    }
    return 0;
}

/* Make sure that n is prime or not prime, according to should_be_prime */
size_t isPrimetest(in Vector!string args, RandomNumberGenerator rng)
{
    BigInt n = BigInt(args[0]);
    bool should_be_prime = (args[1] == "1");
    
    bool isPrime = isPrime(n, rng);
    
    if (isPrime != should_be_prime)
    {
        writeln("ERROR: isPrime");
        writeln("n = ", n);
        writeln(isPrime ~ " != " ~ should_be_prime);
    }
    return 0;
}

unittest
{
	import std.stdio : writeln;
	writeln("Testing bigint/test.d ...");
    import std.array;
    import std.string : strip;
    const string filename = "test_data/mp_valid.dat";
    File test_data = File(filename, "r");
    
    if (test_data.error || test_data.eof)
        throw new StreamIOError("Couldn't open test file " ~ filename);
    
    size_t total_errors = 0;
    size_t errors = 0, alg_count = 0;
    string algorithm;
    bool first = true;
    size_t counter = 0;
    
    AutoSeededRNG rng;
    
    while(!test_data.eof)
    {
        if (test_data.error)
            throw new StreamIOError("File I/O error reading from " ~ filename);
        
        Vector!ubyte line = test_data.readln().strip();
        
        if (line.length == 0) continue;
        
        // Do line continuation
        while(line[line.length-1] == '\\' && !test_data.eof())
        {
            line[] = line.ptr[0 .. line.length-1];
            string nextline = test_data.readln().strip();
            if (nextline.length == 0) continue;
            line ~= nextline;
        }
        
        if (line[0] == '[' && line[line.length - 1] == ']')
        {
            if (!first)
                testReport("Bigint " ~ algorithm, alg_count, errors);
            
            algorithm = line[1 .. line.length - 2 + 1];
            
            total_errors += errors;
            errors = 0;
            alg_count = 0;
            counter = 0;
            
            first = false;
            continue;
        }
        
        Vector!string substr = parse(line[]);
        
        writeln("Testing: " ~ algorithm);
        
        size_t new_errors = 0;
        if (algorithm.canFind("Addition"))
            new_errors = checkAdd(substr);
        else if (algorithm.canFind("Subtraction"))
            new_errors = checkSub(substr);
        else if (algorithm.canFind("Multiplication"))
            new_errors = checkMul(substr);
        else if (algorithm.canFind("Square"))
            new_errors = checkSqr(substr);
        else if (algorithm.canFind("Division"))
            new_errors = checkDiv(substr);
        else if (algorithm.canFind("Modulo"))
            new_errors = checkMod(substr, rng);
        else if (algorithm.canFind("LeftShift"))
            new_errors = checkShl(substr);
        else if (algorithm.canFind("RightShift"))
            new_errors = checkShr(substr);
        else if (algorithm.canFind("ModExp"))
            new_errors = checkPowmod(substr);
        else if (algorithm.canFind("PrimeTest"))
            new_errors = isPrimetest(substr, rng);
        else
            writeln("Unknown MPI test " ~ algorithm);
        
        counter++;
        alg_count++;
        errors += new_errors;
        
        if (new_errors)
            writeln("ERROR: BigInt " ~ algorithm ~ " failed test #" ~ alg_count.to!string);
    }

    
    testReport("BigInt", alg_count, total_errors);
}