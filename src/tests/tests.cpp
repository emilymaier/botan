/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <iostream>
#include <fstream>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/internal/filesystem.h>
#include <botan/internal/bit_ops.h>

#define CATCH_CONFIG_RUNNER
#define CATCH_CONFIG_CONSOLE_WIDTH 60
#define CATCH_CONFIG_COLOUR_NONE
#include "catchy/catch.hpp"

#if defined(BOTAN_HAS_SYSTEM_RNG)
  #include <botan/system_rng.h>
#endif

using namespace Botan;

Botan::RandomNumberGenerator& test_rng()
   {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   return Botan::system_rng();
#else
   static Botan::AutoSeeded_RNG rng;
   return rng;
#endif
   }

size_t warn_about_missing(const std::string& whatever)
   {
   static std::set<std::string> s_already_seen;

   if(s_already_seen.count(whatever) == 0)
      {
      std::cout << "Skipping tests due to missing " << whatever << "\n";
      s_already_seen.insert(whatever);
      }

   return 0;
   }

size_t test_buffers_equal(const std::string& who,
                          const char* provider,
                          const char* what,
                          const byte produced[],
                          size_t produced_size,
                          const byte expected[],
                          size_t expected_size)
   {
   if(produced_size == expected_size && same_mem(produced, expected, expected_size))
      return 0;

   std::ostringstream err;

   err << who;

   if(provider)
      {
      err << " provider " << provider;
      }
   if(what)
      {
      err << " " << what;
      }

   err << " unexpected result";

   if(produced_size != expected_size)
      {
      err << " produced " << produced_size << " bytes expected " << expected_size;
      }

   err << "\n";

   std::vector<byte> xor_diff(std::min(produced_size, expected_size));
   size_t bits_different = 0;

   for(size_t i = 0; i != xor_diff.size(); ++i)
      {
      xor_diff[i] = produced[i] ^ expected[i];
      bits_different += hamming_weight(xor_diff[i]);
      }

   err << "Produced: " << hex_encode(produced, produced_size) << "\n";
   err << "Expected: " << hex_encode(expected, expected_size) << "\n";
   if(bits_different > 0)
      {
      err << "XOR Diff: " << hex_encode(xor_diff)
          << " (" << bits_different << " bits different)\n";
      }

   std::cout << err.str();

   return 1;
   }

size_t run_tests_in_dir(const std::string& dir, std::function<size_t (const std::string&)> fn)
   {
   size_t fails = 0;

   try
      {
      auto files = get_files_recursive(dir);

      if (files.empty())
         std::cout << "Warning: No test files found in '" << dir << "'" << std::endl;

      for(const auto file: files)
         fails += fn(file);
      }
   catch(No_Filesystem_Access)
      {
      std::cout << "Warning: No filesystem access available to read test files in '" << dir << "'" << std::endl;
      }

   return fails;
   }

size_t run_tests(const std::vector<std::pair<std::string, test_fn>>& tests)
   {
   size_t fails = 0;

   for(const auto& row : tests)
      {
      auto name = row.first;
      auto test = row.second;
      try
         {
         fails += test();
         }
      catch(std::exception& e)
         {
         std::cout << name << ": Exception escaped test: " << e.what() << std::endl;
         ++fails;
         }
      catch(...)
         {
         std::cout << name << ": Exception escaped test" << std::endl;
         ++fails;
         }
      }

   // Summary for test suite
   std::cout << "===============" << std::endl;
   test_report("Tests", 0, fails);

   return fails;
   }

void test_report(const std::string& name, size_t ran, size_t failed)
   {
   std::cout << name;

   if(ran > 0)
      std::cout << " " << ran << " tests";

   if(failed)
      std::cout << " " << failed << " FAILs" << std::endl;
   else
      std::cout << " all ok" << std::endl;
   }

size_t run_tests_bb(std::istream& src,
                    const std::string& name_key,
                    const std::string& output_key,
                    bool clear_between_cb,
                    std::function<size_t (std::map<std::string, std::string>)> cb)
   {
   if(!src.good())
      {
      std::cout << "Could not open input file for " << name_key << std::endl;
      return 1;
      }

   std::map<std::string, std::string> vars;
   size_t test_fails = 0, algo_fail = 0;
   size_t test_count = 0, algo_count = 0;

   std::string fixed_name;

   while(src.good())
      {
      std::string line;
      std::getline(src, line);

      if(line == "")
         continue;

      if(line[0] == '#')
         continue;

      if(line[0] == '[' && line[line.size()-1] == ']')
         {
         if(fixed_name != "")
            test_report(fixed_name, algo_count, algo_fail);

         test_count += algo_count;
         test_fails += algo_fail;
         algo_count = 0;
         algo_fail = 0;
         fixed_name = line.substr(1, line.size() - 2);
         vars[name_key] = fixed_name;
         continue;
         }

      const std::string key = line.substr(0, line.find_first_of(' '));
      const std::string val = line.substr(line.find_last_of(' ') + 1, std::string::npos);

      vars[key] = val;

      if(key == name_key)
         fixed_name.clear();

      if(key == output_key)
         {
         //std::cout << vars[name_key] << " " << algo_count << std::endl;
         ++algo_count;
         try
            {
            const size_t fails = cb(vars);

            if(fails)
               {
               std::cout << vars[name_key] << " test " << algo_count << ": " << fails << " failure" << std::endl;
               algo_fail += fails;
               }
            }
         catch(std::exception& e)
            {
            std::cout << vars[name_key] << " test " << algo_count << " failed: " << e.what() << std::endl;
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

size_t run_tests(const std::string& filename,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb)
   {
   std::ifstream vec(filename);

   if(!vec)
      {
      std::cout << "Failure opening " << filename << std::endl;
      return 1;
      }

   return run_tests(vec, name_key, output_key, clear_between_cb, cb);
   }

size_t run_tests(std::istream& src,
                 const std::string& name_key,
                 const std::string& output_key,
                 bool clear_between_cb,
                 std::function<std::string (std::map<std::string, std::string>)> cb)
   {
   return run_tests_bb(src, name_key, output_key, clear_between_cb,
                [name_key,output_key,cb](std::map<std::string, std::string> vars)
                {
                const std::string got = cb(vars);
                if(got != vars[output_key])
                   {
                   std::cout << name_key << ' ' << vars[name_key] << " got " << got
                             << " expected " << vars[output_key] << std::endl;
                   return 1;
                   }
                return 0;
                });
   }

namespace {

int help(char* argv0)
   {
   std::cout << "Usage: " << argv0 << " [suite]" << std::endl;
   std::cout << "Suites: all (default), block, hash, bigint, rsa, ecdsa, ..." << std::endl;
   return 1;
   }

int test_catchy()
   {
   // drop arc and arv for now
   int catchy_result = Catch::Session().run();
   if (catchy_result != 0)
      {
      std::exit(EXIT_FAILURE);
      }
   return 0;
   }

}

int main(int argc, char* argv[])
   {
   if(argc != 1 && argc != 2)
      return help(argv[0]);

   std::string target = "all";

   if(argc == 2)
      target = argv[1];

   if(target == "-h" || target == "--help" || target == "help")
      return help(argv[0]);

   std::vector<std::pair<std::string, test_fn>> tests;

#define DEF_TEST(test) do { if(target == "all" || target == #test) \
      tests.push_back(std::make_pair(#test, test_ ## test));       \
   } while(0)

   // unittesting framework in sub-folder tests/catchy
   DEF_TEST(catchy);

   DEF_TEST(block);
   DEF_TEST(modes);
   DEF_TEST(aead);
   DEF_TEST(ocb);

   DEF_TEST(stream);
   DEF_TEST(hash);
   DEF_TEST(mac);
   DEF_TEST(pbkdf);
   DEF_TEST(kdf);
   DEF_TEST(keywrap);
   DEF_TEST(transform);
   DEF_TEST(rngs);
   DEF_TEST(passhash9);
   DEF_TEST(bcrypt);
   DEF_TEST(cryptobox);
   DEF_TEST(tss);
   DEF_TEST(rfc6979);
   DEF_TEST(srp6);

   DEF_TEST(bigint);

   DEF_TEST(rsa);
   DEF_TEST(rw);
   DEF_TEST(dsa);
   DEF_TEST(nr);
   DEF_TEST(dh);
   DEF_TEST(dlies);
   DEF_TEST(elgamal);
   DEF_TEST(ecc_pointmul);
   DEF_TEST(ecdsa);
   DEF_TEST(gost_3410);
   DEF_TEST(curve25519);
   DEF_TEST(gf2m);
   DEF_TEST(mceliece);
   DEF_TEST(mce);

   DEF_TEST(ecc_unit);
   DEF_TEST(ecc_randomized);
   DEF_TEST(ecdsa_unit);
   DEF_TEST(ecdh_unit);
   DEF_TEST(pk_keygen);
   DEF_TEST(cvc);
   DEF_TEST(x509);
   DEF_TEST(x509_x509test);
   DEF_TEST(nist_x509);
   DEF_TEST(tls);
   DEF_TEST(compression);
   DEF_TEST(fuzzer);

   if(tests.empty())
      {
      std::cout << "No tests selected by target '" << target << "'" << std::endl;
      return 1;
      }

   return run_tests(tests);
   }
