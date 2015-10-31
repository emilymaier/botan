/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_STREAM_CIPHER)
#include <botan/stream_cipher.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_STREAM_CIPHER)

class Stream_Cipher_Tests : public Text_Based_Test
   {
   public:
      Stream_Cipher_Tests(const std::string& data_dir) :
         Text_Based_Test(data_dir, {"Key", "In", "Out"}, {"Nonce"}) {}

      Test::Result run_one_test(const std::string& algo,
                                const std::map<std::string, std::string>& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");
         const std::vector<uint8_t> nonce    = get_opt_bin(vars, "Nonce");

         Test::Result result(algo);

         const std::vector<std::string> providers = Botan::StreamCipher::providers(algo);

         if(providers.empty())
            {
            warn_about_missing("block cipher " + algo);
            return result;
            }

         for(auto&& provider: providers)
            {
            std::unique_ptr<Botan::StreamCipher> cipher(Botan::StreamCipher::create(algo, provider));

            if(!cipher)
               {
               warn_about_missing(algo + " from " + provider);
               continue;
               }

            cipher->set_key(key);

            if(nonce.size())
               cipher->set_iv(nonce.data(), nonce.size());

            std::vector<uint8_t> buf = input;
            cipher->encrypt(buf);

            result.test_eq("encrypt", buf, expected);
            }

         return result;
         }
   };

BOTAN_REGISTER_TEST("stream", Stream_Cipher_Tests(TEST_DATA_DIR "/stream"));

#endif

}


size_t test_stream()
   {
   using namespace Botan_Tests;

   std::vector<Test::Result> results = Test::run_test("stream");

   std::string report;
   size_t fail_cnt = 0;
   Test::summarize(results, report, fail_cnt);

   std::cout << report;
   return fail_cnt;
   }
