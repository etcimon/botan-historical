
#ifndef BOTAN_TESTS_H__
#define BOTAN_TESTS_H__

#include <botan/build.h>
#include <functional>
#include <istream>
#include <map>
#include <string>
#include <vector>

size_t run_tests_bb(File src,
						  string name_key,
						  string output_key,
						  bool clear_between_cb,
						  size_t delegate(string[string]) cb);

size_t run_tests(File src,
					  string name_key,
					  string output_key,
					  bool clear_between_cb,
					  string delegate(string[string]) cb);

size_t run_tests(string filename,
					  string name_key,
					  string output_key,
					  bool clear_between_cb,
					  string delegate(string[string]) cb);

Vector!string list_dir(string dir_path);
size_t run_tests_in_dir(string dir, size_t delegate(string) fn);

// Run a list of tests
typedef std::function<size_t ()> test_fn;

size_t run_tests(input Vector!test_fn tests);
void test_report(string name, size_t ran, size_t failed);

#define TEST(expr, msg) do { if(!(expr)) { ++fails; writeln(msg; } while(0)

#define LIB_SRC_DIR "lib/"
#define TEST_DATA_DIR "src/tests/data/"
#define PK_TEST_DATA_DIR "src/tests/data/pubkey"

int test_main(int argc, char* argv[]);

// Tests using reader framework above
size_t test_block();
size_t test_stream();
size_t test_hash();
size_t test_mac();
size_t test_modes();
size_t test_rngs();
size_t test_hkdf();
size_t test_pbkdf();
size_t test_kdf();
size_t test_aead();
size_t test_transform();

size_t test_rsa();
size_t test_rw();
size_t test_dsa();
size_t test_nr();
size_t test_dh();
size_t test_dlies();
size_t test_elgamal();
size_t test_ecdsa();
size_t test_gost_3410();

// One off tests
size_t test_ocb();
size_t test_keywrap();
size_t test_bcrypt();
size_t test_passhash9();
size_t test_cryptobox();
size_t test_tss();
size_t test_rfc6979();

size_t test_pk_keygen();

size_t test_bigint();

size_t test_ecc_unit();
size_t test_ecdsa_unit();
size_t test_ecdh_unit();

size_t test_x509();
size_t test_cvc();

size_t test_tls();

size_t test_nist_x509();

#endif
