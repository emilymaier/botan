/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
  #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_RSA)

class RSA_ES_KAT_Tests : public PK_Encryption_Decryption_Test
   {
   public:
      RSA_ES_KAT_Tests() : PK_Encryption_Decryption_Test(
         "RSA",
         Test::data_file("pubkey/rsaes.vec"),
         {"E", "P", "Q", "Msg", "Ciphertext"},
         {"Padding", "Nonce"})
         {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(Test::rng(), p, q, e));
         return key;
         }
   };

class RSA_Signature_KAT_Tests : public PK_Signature_Generation_Test
   {
   public:
      RSA_Signature_KAT_Tests() : PK_Signature_Generation_Test(
         "RSA",
         Test::data_file("pubkey/rsa_sig.vec"),
         {"E", "P", "Q", "Msg", "Signature"},
         {"Padding", "Nonce"})
         {}

      std::string default_padding(const VarMap&) const override { return "Raw"; }

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const BigInt p = get_req_bn(vars, "P");
         const BigInt q = get_req_bn(vars, "Q");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(Test::rng(), p, q, e));
         return key;
         }
   };

class RSA_Signature_Verify_Tests : public PK_Signature_Verification_Test
   {
   public:
      RSA_Signature_Verify_Tests() : PK_Signature_Verification_Test(
         "RSA",
         Test::data_file("pubkey/rsa_verify.vec"),
         {"E", "N", "Msg", "Signature"},
         {"Padding"})
         {}

      std::string default_padding(const VarMap&) const override { return "Raw"; }

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const BigInt n = get_req_bn(vars, "N");
         const BigInt e = get_req_bn(vars, "E");

         std::unique_ptr<Botan::Public_Key> key(new Botan::RSA_PublicKey(n, e));
         return key;
         }
   };

class RSA_Keygen_Tests : public PK_Key_Generation_Test
   {
   public:
      std::vector<std::string> keygen_params() const override { return { "1024", "1280" }; }

      std::unique_ptr<Botan::Private_Key> make_key(Botan::RandomNumberGenerator& rng,
                                                   const std::string& param) const override
         {
         size_t bits = Botan::to_u32bit(param);
         std::unique_ptr<Botan::Private_Key> key(new Botan::RSA_PrivateKey(rng, bits));
         return key;
         }
   };

BOTAN_REGISTER_TEST("rsa_encrypt", RSA_ES_KAT_Tests);
BOTAN_REGISTER_TEST("rsa_sign", RSA_Signature_KAT_Tests);
BOTAN_REGISTER_TEST("rsa_verify", RSA_Signature_Verify_Tests);
BOTAN_REGISTER_TEST("rsa_keygen", RSA_Keygen_Tests);

#endif

}

}
