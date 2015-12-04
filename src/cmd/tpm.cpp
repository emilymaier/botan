/*
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "apps.h"

#if defined(BOTAN_HAS_TPM)

#include <botan/tpm.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>

namespace {

std::string tpm_pin(const std::string& prompt)
   {
   std::cout << "Enter PIN for " << prompt << ": ";
   //TODO getpass
   std::string pin;
   std::cin >> pin;
   return pin;
   }

int tpm(int argc, char* argv[])
   {
   TPM_Context ctx(tpm_pin, nullptr);

   std::vector<std::string> keys = TPM_PrivateKey::registered_keys(ctx);

   for(auto&& key: keys)
      std::cout << key << "\n";

   TPM_RNG tpm_rng(ctx);

   //TPM_PrivateKey key(ctx, "tpmkey:uuid=5821592A-37514-388D-D384-D43B16145AC;storage=system");
   TPM_PrivateKey key(ctx, "5821592A-37514-388D-D384-D43B16145AC", TPM_Storage_Type::System);
   //TPM_PrivateKey key(ctx, "D72B75DC-81954-291C-F7CB-34C872EC1BD", TPM_Storage_Type::User);
   //TPM_PrivateKey key(ctx, 1024, "pass");

   //std::cout << key.register_key(TPM_Storage_Type::User) << "\n";

   PK_Signer signer(key, "EMSA3(SHA-256)");
   signer.update("hello");

   std::vector<uint8_t> sig = signer.signature(tpm_rng);

   std::unique_ptr<Public_Key> rsa_pub = key.public_key();

   std::cout << X509::PEM_encode(*rsa_pub);

   PK_Verifier verifier(*rsa_pub, "EMSA3(SHA-256)");
   verifier.update("hello");

   std::cout << "Signature good? " << verifier.check_signature(sig) << "\n";
   return 0;
   }

REGISTER_APP(tpm);

}

#endif
