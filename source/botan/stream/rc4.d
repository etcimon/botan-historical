/*
* RC4
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.rc4;

import botan.stream.stream_cipher;
import botan.utils.types;
import botan.utils.xor_buf;
import botan.utils.rounding;

/**
* RC4 stream cipher
*/
final class RC4 : StreamCipher
{
public:
	/*
	* Combine cipher stream with message
	*/
	void cipher(in ubyte* input, ubyte* output)
	{
		while(length >= buffer.length - position)
		{
			xor_buf(output, input, &buffer[position], buffer.length - position);
			length -= (buffer.length - position);
			input += (buffer.length - position);
			output += (buffer.length - position);
			generate();
		}
		xor_buf(output, input, &buffer[position], length);
		position += length;
	}

	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		zap(state);
		zap(buffer);
		position = X = Y = 0;
	}

	/*
	* Return the name of this type
	*/
	@property string name() const
	{
		if (SKIP == 0)	return "RC4";
		if (SKIP == 256) return "MARK-4";
		else				return "RC4_skip(" ~ std.conv.to!string(SKIP) ~ ")";
	}

	RC4 clone() const { return new RC4(SKIP); }

	Key_Length_Specification key_spec() const
	{
		return Key_Length_Specification(1, 256);
	}

	/**
	* @param skip skip this many initial bytes in the keystream
	*/
	this(size_t s = 0) { SKIP = s; }

	~this() { clear(); }
private:
	/*
	* RC4 Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		state.resize(256);
		buffer.resize(round_up!size_t(DEFAULT_BUFFERSIZE, 4));
		
		position = X = Y = 0;
		
		for (size_t i = 0; i != 256; ++i)
			state[i] = cast(ubyte)(i);
		
		for (size_t i = 0, state_index = 0; i != 256; ++i)
		{
			state_index = (state_index + key[i % length] + state[i]) % 256;
			std.algorithm.swap(state[i], state[state_index]);
		}
		
		for (size_t i = 0; i <= SKIP; i += buffer.length)
			generate();
		
		position += (SKIP % buffer.length);
	}


	/*
	* Generate cipher stream
	*/
	void generate()
	{
		ubyte SX, SY;
		for (size_t i = 0; i != buffer.length; i += 4)
		{
			SX = state[X+1]; Y = (Y + SX) % 256; SY = state[Y];
			state[X+1] = SY; state[Y] = SX;
			buffer[i] = state[(SX + SY) % 256];
			
			SX = state[X+2]; Y = (Y + SX) % 256; SY = state[Y];
			state[X+2] = SY; state[Y] = SX;
			buffer[i+1] = state[(SX + SY) % 256];
			
			SX = state[X+3]; Y = (Y + SX) % 256; SY = state[Y];
			state[X+3] = SY; state[Y] = SX;
			buffer[i+2] = state[(SX + SY) % 256];
			
			X = (X + 4) % 256;
			SX = state[X]; Y = (Y + SX) % 256; SY = state[Y];
			state[X] = SY; state[Y] = SX;
			buffer[i+3] = state[(SX + SY) % 256];
		}
		position = 0;
	}

	const size_t SKIP;

	ubyte X, Y;
	Secure_Vector!ubyte state;

	Secure_Vector!ubyte buffer;
	size_t position;
};
