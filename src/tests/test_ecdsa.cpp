/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_ECDSA)
  #include "test_pubkey.h"
  #include <botan/ecdsa.h>
  #include <botan/oids.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_ECDSA)

class ECDSA_Signature_KAT_Tests : public PK_Signature_Generation_Test
   {
   public:
      ECDSA_Signature_KAT_Tests() : PK_Signature_Generation_Test(
         "ECDSA",
         Test::data_file("pubkey/ecdsa.vec"),
         {"Group", "X", "Hash", "Msg", "Signature"},
         {},
         false)
         {}

      std::unique_ptr<Botan::Private_Key> load_private_key(const VarMap& vars) override
         {
         const std::string group_id = get_req_str(vars, "Group");
         const BigInt x = get_req_bn(vars, "X");
         Botan::EC_Group group(OIDS::lookup(group_id));

         std::unique_ptr<Botan::Private_Key> key(new Botan::ECDSA_PrivateKey(Test::rng(), group, x));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + get_req_str(vars, "Hash") + ")";
         }
   };

BOTAN_REGISTER_TEST("ecdsa", ECDSA_Signature_KAT_Tests);

#endif

}

}

size_t test_ecdsa()
   {
   return Botan_Tests::basic_error_report("ecdsa");
   }
