/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include <botan/block_cipher.h>

namespace Botan_Tests {

class Block_Cipher_Tests : public Text_Based_Test
   {
   public:
      Block_Cipher_Tests() : Text_Based_Test(Test::data_dir("block"), {"Key", "In", "Out"}) {}

      Test::Result run_one_test(const std::string& algo, const VarMap& vars) override
         {
         const std::vector<uint8_t> key      = get_req_bin(vars, "Key");
         const std::vector<uint8_t> input    = get_req_bin(vars, "In");
         const std::vector<uint8_t> expected = get_req_bin(vars, "Out");

         Test::Result result(algo);

         const std::vector<std::string> providers = Botan::BlockCipher::providers(algo);

         if(providers.empty())
            {
            warn_about_missing("block cipher " + algo);
            return result;
            }

         for(auto&& provider: providers)
            {
            std::unique_ptr<Botan::BlockCipher> cipher(Botan::BlockCipher::create(algo, provider));

            if(!cipher)
               {
               warn_about_missing(algo + " from " + provider);
               continue;
               }

            cipher->set_key(key);
            std::vector<uint8_t> buf = input;

            cipher->encrypt(buf);

            result.test_eq(provider, "encrypt", buf, expected);

            // always decrypt expected ciphertext vs what we produced above
            buf = expected;
            cipher->decrypt(buf);

            result.test_eq(provider, "decrypt", buf, input);
            }

         return result;
         }

   };

BOTAN_REGISTER_TEST("block", Block_Cipher_Tests);

}

size_t test_block()
   {
   return Botan_Tests::basic_error_report("block");
   }
