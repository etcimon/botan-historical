/*
* Pipe
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pipe;
import botan.internal.out_buf;
import botan.secqueue;
import botan.parsing;
namespace {

/*
* A Filter that does nothing
*/
class Null_Filter : Filter
{
	public:
		void write(in ubyte* input, size_t length)
		{ send(input, length); }

		string name() const { return "Null"; }
};

}

/*
* Pipe Constructor
*/
Pipe::Pipe(Filter* f1, Filter* f2, Filter* f3, Filter* f4)
{
	init();
	append(f1);
	append(f2);
	append(f3);
	append(f4);
}

/*
* Pipe Constructor
*/
Pipe::Pipe(std::initializer_list<Filter*> args)
{
	init();

	for (auto i = args.begin(); i != args.end(); ++i)
		append(*i);
}

/*
* Pipe Destructor
*/
Pipe::~this()
{
	destruct(pipe);
	delete outputs;
}

/*
* Initialize the Pipe
*/
void Pipe::init()
{
	outputs = new Output_Buffers;
	pipe = null;
	default_read = 0;
	inside_msg = false;
}

/*
* Reset the Pipe
*/
void Pipe::reset()
{
	destruct(pipe);
	pipe = null;
	inside_msg = false;
}

/*
* Destroy the Pipe
*/
void Pipe::destruct(Filter* to_kill)
{
	if (!to_kill || cast(SecureQueue*)(to_kill))
		return;
	for (size_t j = 0; j != to_kill.total_ports(); ++j)
		destruct(to_kill.next[j]);
	delete to_kill;
}

/*
* Test if the Pipe has any data in it
*/
bool Pipe::end_of_data() const
{
	return (remaining() == 0);
}

/*
* Set the default read message
*/
void Pipe::set_default_msg(message_id msg)
{
	if (msg >= message_count())
		throw new Invalid_Argument("Pipe::set_default_msg: msg number is too high");
	default_read = msg;
}

/*
* Process a full message at once
*/
void Pipe::process_msg(in ubyte* input, size_t length)
{
	start_msg();
	write(input, length);
	end_msg();
}

/*
* Process a full message at once
*/
void Pipe::process_msg(in SafeVector!ubyte input)
{
	process_msg(&input[0], input.size());
}

void Pipe::process_msg(in Vector!ubyte input)
{
	process_msg(&input[0], input.size());
}

/*
* Process a full message at once
*/
void Pipe::process_msg(in string input)
{
	process_msg(cast(const ubyte*)(input.data()), input.length());
}

/*
* Process a full message at once
*/
void Pipe::process_msg(DataSource input)
{
	start_msg();
	write(input);
	end_msg();
}

/*
* Start a new message
*/
void Pipe::start_msg()
{
	if (inside_msg)
		throw new Invalid_State("Pipe::start_msg: Message was already started");
	if (pipe == null)
		pipe = new Null_Filter;
	find_endpoints(pipe);
	pipe.new_msg();
	inside_msg = true;
}

/*
* End the current message
*/
void Pipe::end_msg()
{
	if (!inside_msg)
		throw new Invalid_State("Pipe::end_msg: Message was already ended");
	pipe.finish_msg();
	clear_endpoints(pipe);
	if (cast(Null_Filter*)(pipe))
	{
		delete pipe;
		pipe = null;
	}
	inside_msg = false;

	outputs.retire();
}

/*
* Find the endpoints of the Pipe
*/
void Pipe::find_endpoints(Filter* f)
{
	for (size_t j = 0; j != f.total_ports(); ++j)
		if (f.next[j] && !cast(SecureQueue*)(f.next[j]))
			find_endpoints(f.next[j]);
		else
		{
			SecureQueue* q = new SecureQueue;
			f.next[j] = q;
			outputs.add(q);
		}
}

/*
* Remove the SecureQueues attached to the Filter
*/
void Pipe::clear_endpoints(Filter* f)
{
	if (!f) return;
	for (size_t j = 0; j != f.total_ports(); ++j)
	{
		if (f.next[j] && cast(SecureQueue*)(f.next[j]))
			f.next[j] = null;
		clear_endpoints(f.next[j]);
	}
}

/*
* Append a Filter to the Pipe
*/
void Pipe::append(Filter* filter)
{
	if (inside_msg)
		throw new Invalid_State("Cannot append to a Pipe while it is processing");
	if (!filter)
		return;
	if (cast(SecureQueue*)(filter))
		throw new Invalid_Argument("Pipe::append: SecureQueue cannot be used");
	if (filter.owned)
		throw new Invalid_Argument("Filters cannot be shared among multiple Pipes");

	filter.owned = true;

	if (!pipe) pipe = filter;
	else		pipe.attach(filter);
}

/*
* Prepend a Filter to the Pipe
*/
void Pipe::prepend(Filter* filter)
{
	if (inside_msg)
		throw new Invalid_State("Cannot prepend to a Pipe while it is processing");
	if (!filter)
		return;
	if (cast(SecureQueue*)(filter))
		throw new Invalid_Argument("Pipe::prepend: SecureQueue cannot be used");
	if (filter.owned)
		throw new Invalid_Argument("Filters cannot be shared among multiple Pipes");

	filter.owned = true;

	if (pipe) filter.attach(pipe);
	pipe = filter;
}

/*
* Pop a Filter off the Pipe
*/
void Pipe::pop()
{
	if (inside_msg)
		throw new Invalid_State("Cannot pop off a Pipe while it is processing");

	if (!pipe)
		return;

	if (pipe.total_ports() > 1)
		throw new Invalid_State("Cannot pop off a Filter with multiple ports");

	Filter* f = pipe;
	size_t owns = f.owns();
	pipe = pipe.next[0];
	delete f;

	while(owns--)
	{
		f = pipe;
		pipe = pipe.next[0];
		delete f;
	}
}

/*
* Return the number of messages in this Pipe
*/
Pipe::message_id Pipe::message_count() const
{
	return outputs.message_count();
}

/*
* Static Member Variables
*/
const Pipe::message_id Pipe::LAST_MESSAGE =
	cast(Pipe::message_id)(-2);

const Pipe::message_id Pipe::DEFAULT_MESSAGE =
	cast(Pipe::message_id)(-1);

}
