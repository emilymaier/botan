/*
* (C) 2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_PUBLIC_KEY_CRYPTO)

#include "test_rng.h"
#include "test_pubkey.h"

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdlib>
#include <memory>

#include <botan/oids.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>
#include <botan/numthry.h>
#include <botan/hex.h>

#if defined(BOTAN_HAS_RSA)
  #include <botan/rsa.h>
#endif

#if defined(BOTAN_HAS_DSA)
  #include <botan/dsa.h>
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  #include <botan/dh.h>
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
  #include <botan/nr.h>
#endif

#if defined(BOTAN_HAS_RW)
  #include <botan/rw.h>
#endif

#if defined(BOTAN_HAS_ELGAMAL)
  #include <botan/elgamal.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
  #include <botan/gost_3410.h>
#endif

#if defined(BOTAN_HAS_DLIES)
  #include <botan/dlies.h>
  #include <botan/kdf.h>
#endif

namespace Botan_Tests {

Test::Result
PK_Signature_Generation_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> message   = get_req_bin(vars, "Msg");
   const std::vector<uint8_t> signature = get_req_bin(vars, "Signature");
   const std::string padding = get_opt_str(vars, "Padding", default_padding(vars));

   std::unique_ptr<RandomNumberGenerator> rng;
   if(vars.count("Nonce"))
      {
      rng.reset(new Fixed_Output_RNG(get_req_bin(vars, "Nonce")));
      }

   Test::Result result(algo_name() + "/" + padding + " signature generation");

   std::unique_ptr<Private_Key> privkey = load_private_key(vars);
   std::unique_ptr<Public_Key> pubkey(X509::load_key(X509::BER_encode(*privkey)));

   Botan::PK_Signer signer(*privkey, padding);
   Botan::PK_Verifier verifier(*pubkey, padding);

   const std::vector<byte> generated_signature = signer.sign_message(message, rng ? *rng : Test::rng());
   result.test_eq("generated signature matches KAT", generated_signature, signature);

   result.test_eq("generated signature valid", verifier.verify_message(message, generated_signature), true);
   check_invalid_signatures(result, verifier, message, signature);
   result.test_eq("correct signature valid", verifier.verify_message(message, signature), true);

   return result;
   }

Test::Result
PK_Signature_Verification_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> message   = get_req_bin(vars, "Msg");
   const std::vector<uint8_t> signature = get_req_bin(vars, "Signature");
   const std::string padding = get_opt_str(vars, "Padding", default_padding(vars));
   std::unique_ptr<Public_Key> pubkey = load_public_key(vars);

   Test::Result result(algo_name() + "/" + padding + " signature verification");

   Botan::PK_Verifier verifier(*pubkey, padding);

   result.test_eq("correct signature valid", verifier.verify_message(message, signature), true);

   check_invalid_signatures(result, verifier, message, signature);

   return result;
   }

Test::Result
PK_Encryption_Decryption_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> plaintext  = get_req_bin(vars, "Msg");
   const std::vector<uint8_t> ciphertext = get_req_bin(vars, "Ciphertext");

   const std::string padding = get_opt_str(vars, "Padding", default_padding(vars));

   std::unique_ptr<RandomNumberGenerator> kat_rng;
   if(vars.count("Nonce"))
      {
      kat_rng.reset(new Fixed_Output_RNG(get_req_bin(vars, "Nonce")));
      }

   Test::Result result(algo_name() + "/" + padding + " encryption/decryption");

   std::unique_ptr<Private_Key> privkey = load_private_key(vars);
   //std::unique_ptr<Public_Key> pubkey(X509::load_key(X509::BER_encode(*privkey)));

   Botan::PK_Encryptor_EME encryptor(*privkey, padding);
   result.test_eq("encryption", encryptor.encrypt(plaintext, kat_rng ? *kat_rng : Test::rng()), ciphertext);

   Botan::PK_Decryptor_EME decryptor(*privkey, padding);
   result.test_eq("decryption", decryptor.decrypt(ciphertext), plaintext);

   check_invalid_ciphertexts(result, decryptor, plaintext, ciphertext);

   return result;
   }

Test::Result PK_Key_Agreement_Test::run_one_test(const std::string&, const VarMap& vars)
   {
   const std::vector<uint8_t> shared = get_req_bin(vars, "K");
   const std::string kdf = get_opt_str(vars, "KDF", default_kdf(vars));

   Test::Result result(algo_name() + "/" + kdf + " key agreement");

   std::unique_ptr<Private_Key> privkey = load_our_key(vars);
   const std::vector<byte> pubkey = load_their_key(vars);

   const size_t key_len = get_opt_sz(vars, "OutLen", 0);

   PK_Key_Agreement kas(*privkey, kdf);

   result.test_eq("agreement", kas.derive_key(key_len, pubkey).bits_of(), shared);

   return result;
   }

}


using namespace Botan;

namespace {

void dump_data(const std::vector<byte>& out,
               const std::vector<byte>& expected)
   {
   std::cout << "Got: " << hex_encode(out) << std::endl;
   std::cout << "Exp: " << hex_encode(expected) << std::endl;
   }

size_t validate_save_and_load(const Private_Key* priv_key,
                              RandomNumberGenerator& rng)
   {
   std::string name = priv_key->algo_name();

   size_t fails = 0;
   std::string pub_pem = X509::PEM_encode(*priv_key);

   try
      {
      DataSource_Memory input_pub(pub_pem);
      std::unique_ptr<Public_Key> restored_pub(X509::load_key(input_pub));

      if(!restored_pub.get())
         {
         std::cout << "Could not recover " << name << " public key" << std::endl;
         ++fails;
         }
      else if(restored_pub->check_key(rng, true) == false)
         {
         std::cout << "Restored pubkey failed self tests " << name << std::endl;
         ++fails;
         }
      }
   catch(std::exception& e)
      {
      std::cout << "Exception during load of " << name
                << " key: " << e.what() << std::endl;
      std::cout << "PEM for pubkey was:\n" << pub_pem << std::endl;
      ++fails;
      }

   std::string priv_pem = PKCS8::PEM_encode(*priv_key);

   try
      {
      DataSource_Memory input_priv(priv_pem);
      std::unique_ptr<Private_Key> restored_priv(
         PKCS8::load_key(input_priv, rng));

      if(!restored_priv.get())
         {
         std::cout << "Could not recover " << name << " privlic key" << std::endl;
         ++fails;
         }
      else if(restored_priv->check_key(rng, true) == false)
         {
         std::cout << "Restored privkey failed self tests " << name << std::endl;
         ++fails;
         }
      }
   catch(std::exception& e)
      {
      std::cout << "Exception during load of " << name
                << " key: " << e.what() << std::endl;
      std::cout << "PEM for privkey was:\n" << priv_pem << std::endl;
      ++fails;
      }

   return fails;
   }

byte nonzero_byte(RandomNumberGenerator& rng)
   {
   byte b = 0;
   while(b == 0)
      b = rng.next_byte();
   return b;
   }

}

#define PK_TEST(expr, msg)                                \
   do {                                                \
      const bool test_result = expr;                           \
      if(!test_result)                                           \
         {                                             \
         std::cout << "Test " << #expr << " failed: " << msg << std::endl; \
         ++fails;                                      \
         }                                             \
   } while(0)

size_t validate_encryption(PK_Encryptor& e, PK_Decryptor& d,
                           const std::string& algo, const std::string& input,
                           const std::string& random, const std::string& exp)
   {
   std::vector<byte> message = hex_decode(input);
   std::vector<byte> expected = hex_decode(exp);
   Fixed_Output_RNG kat_rng(hex_decode(random));

   size_t fails = 0;

   const std::vector<byte> ctext = e.encrypt(message, kat_rng);
   if(ctext != expected)
      {
      std::cout << "FAILED (encrypt): " << algo << std::endl;
      dump_data(ctext, expected);
      ++fails;
      }

   std::vector<byte> decrypted = unlock(d.decrypt(ctext));

   if(decrypted != message)
      {
      std::cout << "FAILED (decrypt): " << algo << std::endl;
      dump_data(decrypted, message);
      ++fails;
      }

   if(algo.find("/Raw") == std::string::npos)
      {
      auto& rng = test_rng();

      for(size_t i = 0; i != ctext.size(); ++i)
         {
         std::vector<byte> bad_ctext = ctext;

         bad_ctext[i] ^= nonzero_byte(rng);

         BOTAN_ASSERT(bad_ctext != ctext, "Made them different");

         try
            {
            auto bad_ptext = unlock(d.decrypt(bad_ctext));
            std::cout << algo << " failed - decrypted bad data" << std::endl;
            std::cout << hex_encode(bad_ctext) << " -> " << hex_encode(bad_ptext) << std::endl;
            std::cout << hex_encode(ctext) << " -> " << hex_encode(decrypted) << std::endl;

            // Ignore PKCS #1 failures as they do occur occasionally (million message attack)
            const bool is_pkcs1 = algo.find("/EME-PKCS1-v1_5") != std::string::npos;

            if(is_pkcs1)
               std::cout << "Ignoring PKCS #1 failure" << std::endl;
            else
               ++fails;
            }
         catch(...) {}
         }
      }

   return fails;
   }

size_t validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                          const std::string& input,
                          RandomNumberGenerator& rng,
                          const std::string& exp)
   {
   return validate_signature(v, s, algo, input, rng, rng, exp);
   }

size_t validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                          const std::string& input,
                          RandomNumberGenerator& signer_rng,
                          RandomNumberGenerator& test_rng,
                          const std::string& exp)
   {
   std::vector<byte> message = hex_decode(input);
   std::vector<byte> expected = hex_decode(exp);
   std::vector<byte> sig = s.sign_message(message, signer_rng);

   size_t fails = 0;

   if(sig != expected)
      {
      std::cout << "FAILED (sign): " << algo << std::endl;
      dump_data(sig, expected);
      ++fails;
      }

   PK_TEST(v.verify_message(message, sig), "Correct signature is valid");

   for(size_t i = 0; i != 5; ++i)
      {
      auto bad_sig = sig;

      const size_t idx = (test_rng.next_byte() * 256 + test_rng.next_byte()) % sig.size();
      bad_sig[idx] ^= nonzero_byte(test_rng);

      PK_TEST(!v.verify_message(message, bad_sig), "Incorrect signature is invalid");
      }

   zero_mem(sig.data(), sig.size());

   PK_TEST(!v.verify_message(message, sig), "All-zero signature is invalid");

   return fails;
   }

size_t validate_signature(PK_Verifier& v, PK_Signer& s, const std::string& algo,
                          const std::string& input,
                          RandomNumberGenerator& rng,
                          const std::string& random,
                          const std::string& exp)
   {
   Fixed_Output_RNG fixed_rng(hex_decode(random));

   return validate_signature(v, s, algo, input, fixed_rng, rng, exp);
   }

size_t validate_kas(PK_Key_Agreement& kas, const std::string& algo,
                    const std::vector<byte>& pubkey, const std::string& output,
                    size_t keylen)
   {
   std::vector<byte> expected = hex_decode(output);

   std::vector<byte> got = unlock(kas.derive_key(keylen, pubkey).bits_of());

   size_t fails = 0;

   if(got != expected)
      {
      std::cout << "FAILED: " << algo << std::endl;
      dump_data(got, expected);
      ++fails;
      }

   return fails;
   }

size_t test_pk_keygen()
   {
   auto& rng = test_rng();

   size_t tests = 0;
   size_t fails = 0;

#define DL_KEY(TYPE, GROUP)                             \
   {                                                    \
   TYPE key(rng, DL_Group(GROUP));                      \
   key.check_key(rng, true);                            \
   ++tests;                                             \
   fails += validate_save_and_load(&key, rng);          \
   }

#define EC_KEY(TYPE, GROUP)                             \
   {                                                    \
   TYPE key(rng, EC_Group(OIDS::lookup(GROUP)));        \
   key.check_key(rng, true);                            \
   ++tests;                                             \
   fails += validate_save_and_load(&key, rng);          \
   }

#if defined(BOTAN_HAS_RSA)
      {
      RSA_PrivateKey rsa1024(rng, 1024);
      rsa1024.check_key(rng, true);
      ++tests;
      fails += validate_save_and_load(&rsa1024, rng);

      RSA_PrivateKey rsa2048(rng, 2048);
      rsa2048.check_key(rng, true);
      ++tests;
      fails += validate_save_and_load(&rsa2048, rng);
      }
#endif

#if defined(BOTAN_HAS_RW)
      {
      RW_PrivateKey rw1024(rng, 1024);
      rw1024.check_key(rng, true);
      ++tests;
      fails += validate_save_and_load(&rw1024, rng);
      }
#endif

#if defined(BOTAN_HAS_DSA)
   DL_KEY(DSA_PrivateKey, "dsa/jce/1024");
   DL_KEY(DSA_PrivateKey, "dsa/botan/2048");
   DL_KEY(DSA_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
   DL_KEY(DH_PrivateKey, "modp/ietf/1024");
   DL_KEY(DH_PrivateKey, "modp/ietf/2048");
   DL_KEY(DH_PrivateKey, "modp/ietf/4096");
   DL_KEY(DH_PrivateKey, "dsa/jce/1024");
#endif

#if defined(BOTAN_HAS_NYBERG_RUEPPEL)
   DL_KEY(NR_PrivateKey, "dsa/jce/1024");
   DL_KEY(NR_PrivateKey, "dsa/botan/2048");
   DL_KEY(NR_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_ELGAMAL)
   DL_KEY(ElGamal_PrivateKey, "modp/ietf/1024");
   DL_KEY(ElGamal_PrivateKey, "dsa/jce/1024");
   DL_KEY(ElGamal_PrivateKey, "dsa/botan/2048");
   DL_KEY(ElGamal_PrivateKey, "dsa/botan/3072");
#endif

#if defined(BOTAN_HAS_ECDSA)
   EC_KEY(ECDSA_PrivateKey, "secp112r1");
   EC_KEY(ECDSA_PrivateKey, "secp128r1");
   EC_KEY(ECDSA_PrivateKey, "secp160r1");
   EC_KEY(ECDSA_PrivateKey, "secp192r1");
   EC_KEY(ECDSA_PrivateKey, "secp224r1");
   EC_KEY(ECDSA_PrivateKey, "secp256r1");
   EC_KEY(ECDSA_PrivateKey, "secp384r1");
   EC_KEY(ECDSA_PrivateKey, "secp521r1");
#endif

#if defined(BOTAN_HAS_GOST_34_10_2001)
   EC_KEY(GOST_3410_PrivateKey, "gost_256A");
   EC_KEY(GOST_3410_PrivateKey, "secp112r1");
   EC_KEY(GOST_3410_PrivateKey, "secp128r1");
   EC_KEY(GOST_3410_PrivateKey, "secp160r1");
   EC_KEY(GOST_3410_PrivateKey, "secp192r1");
   EC_KEY(GOST_3410_PrivateKey, "secp224r1");
   EC_KEY(GOST_3410_PrivateKey, "secp256r1");
   EC_KEY(GOST_3410_PrivateKey, "secp384r1");
   EC_KEY(GOST_3410_PrivateKey, "secp521r1");
#endif

   test_report("PK keygen", tests, fails);

   return fails;
   }

#else

SKIP_TEST(pk_keygen);

#endif // BOTAN_HAS_PUBLIC_KEY_CRYPTO
