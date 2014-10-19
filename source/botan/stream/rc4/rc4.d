/*
* RC4
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.rc4;
import botan.internal.xor_buf;
import botan.utils.rounding;
/*
* Combine cipher stream with message
*/
void RC4::cipher(in ubyte* input, ubyte* output)
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
* Generate cipher stream
*/
void RC4::generate()
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

/*
* RC4 Key Schedule
*/
void RC4::key_schedule(in ubyte* key, size_t length)
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
* Return the name of this type
*/
string RC4::name() const
{
	if (SKIP == 0)	return "RC4";
	if (SKIP == 256) return "MARK-4";
	else				return "RC4_skip(" ~ std.conv.to!string(SKIP) ~ ")";
}

/*
* Clear memory of sensitive data
*/
void RC4::clear()
{
	zap(state);
	zap(buffer);
	position = X = Y = 0;
}

/*
* RC4 Constructor
*/
RC4::RC4(size_t s) : SKIP(s) {}

}
