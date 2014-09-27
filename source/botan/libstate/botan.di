/*
* A vague catch all include file for Botan
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.init;
import botan.lookup;
import botan.libstate;
import botan.version;
import botan.parsing;

import botan.rng;

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
  import botan.auto_rng;
#endif

#endif
