/*
* File Tree Walking EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy.entropy_src;
class File_Descriptor_Source
{
	public:
		abstract int next_fd();
		~this() {}
};

/**
* File Tree Walking Entropy Source
*/
class ProcWalking_EntropySource : EntropySource
{
	public:
		string name() const { return "Proc Walker"; }

		void poll(ref Entropy_Accumulator accum);

		ProcWalking_EntropySource(in string root_dir) :
			m_path(root_dir), m_dir(null) {}

	private:
		const string m_path;
		Unique!File_Descriptor_Source m_dir;
};