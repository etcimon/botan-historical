/*
* Cipher Modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.algo_base.transform;
/**
* Interface for cipher modes
*/
class Cipher_Mode : public Keyed_Transform
{
	public:
		/**
		* Returns true iff this mode provides authentication as well as
		* confidentiality.
		*/
		abstract bool authenticated() const { return false; }
};