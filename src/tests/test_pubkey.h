/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_TEST_PUBKEY_H__
#define BOTAN_TEST_PUBKEY_H__

#include "tests.h"
#include <botan/pubkey.h>

namespace Botan_Tests {

class PK_Signature_Generation_Test : public Text_Based_Test
   {
   public:
      PK_Signature_Generation_Test(const std::string& algo,
                                   const std::string& test_src,
                                   const std::vector<std::string>& required_keys,
                                   const std::vector<std::string>& optional_keys = {}) :
         Text_Based_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::string default_padding(const VarMap&) const
         {
         throw std::runtime_error("No default padding scheme set for " + algo_name());
         }

      virtual std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) = 0;
   private:
      Test::Result run_one_test(const std::string&, const VarMap& vars) override;
   };

class PK_Signature_Verification_Test : public Text_Based_Test
   {
   public:
      PK_Signature_Verification_Test(const std::string& algo,
                                     const std::string& test_src,
                                     const std::vector<std::string>& required_keys,
                                     const std::vector<std::string>& optional_keys = {}) :
         Text_Based_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::string default_padding(const VarMap&) const
         {
         throw std::runtime_error("No default padding scheme set for " + algo_name());
         }

      virtual std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) = 0;
   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) override;
   };

class PK_Encryption_Decryption_Test : public Text_Based_Test
   {
   public:
      PK_Encryption_Decryption_Test(const std::string& algo,
                                    const std::string& test_src,
                                    const std::vector<std::string>& required_keys,
                                    const std::vector<std::string>& optional_keys = {}) :
         Text_Based_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) = 0;

      virtual std::string default_padding(const VarMap&) const { return "Raw"; }
   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) override;
};

class PK_Key_Agreement_Test : public Text_Based_Test
   {
   public:
      PK_Key_Agreement_Test(const std::string& algo,
                            const std::string& test_src,
                            const std::vector<std::string>& required_keys,
                            const std::vector<std::string>& optional_keys = {}) :
         Text_Based_Test(algo, test_src, required_keys, optional_keys) {}

      virtual std::unique_ptr<Botan::Private_Key> load_our_key(const VarMap& vars) = 0;
      virtual std::vector<uint8_t> load_their_key(const VarMap& vars) = 0;

      virtual std::string default_kdf(const VarMap&) const { return "Raw"; }

   private:
      Test::Result run_one_test(const std::string& header, const VarMap& vars) override;
   };

void check_invalid_signatures(Test::Result& result,
                              Botan::PK_Verifier& verifier,
                              const std::vector<uint8_t>& message,
                              const std::vector<uint8_t>& signature);

void check_invalid_ciphertexts(Test::Result& result,
                               Botan::PK_Decryptor& decryptor,
                               const std::vector<uint8_t>& plaintext,
                               const std::vector<uint8_t>& ciphertext);

}

#endif
