/*
* (C) 2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
  #include <botan/oids.h>
  #include "test_pubkey.h"
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_GOST_34_10_2001)

class GOST_3410_2001_Verification_Tests : public PK_Signature_Verification_Test
   {
   public:
      GOST_3410_2001_Verification_Tests() : PK_Signature_Verification_Test(
         "GOST 34.10-2001 verification",
         Test::data_file("pubkey/gost_3410.vec"),
         {"Group", "Pubkey", "Hash", "Msg", "Signature"})
         {}

      std::unique_ptr<Botan::Public_Key> load_public_key(const VarMap& vars) override
         {
         const std::string group_id = get_req_str(vars, "Group");
         Botan::EC_Group group(OIDS::lookup(group_id));
         const Botan::PointGFp public_point = Botan::OS2ECP(get_req_bin(vars, "Pubkey"), group.get_curve());

         std::unique_ptr<Botan::Public_Key> key(new Botan::GOST_3410_PublicKey(group, public_point));
         return key;
         }

      std::string default_padding(const VarMap& vars) const override
         {
         return "EMSA1(" + get_req_str(vars, "Hash") + ")";
         }
   };

BOTAN_REGISTER_TEST("gost_3410_verify", GOST_3410_2001_Verification_Tests);

#endif

}

}

size_t test_gost_3410()
   {
   return Botan_Tests::basic_error_report("gost_3410_verify");
   }
