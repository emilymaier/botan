/*
* RSA
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/rsa.h>
#include <botan/libstate.h>
#include <botan/parsing.h>
#include <botan/numthry.h>
#include <botan/keypair.h>

namespace Botan {

/*
* Create a RSA private key
*/
RSA_PrivateKey::RSA_PrivateKey(RandomNumberGenerator& rng,
                               u32bit bits, u32bit exp)
   {
   if(bits < 512)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             to_string(bits) + " bits long");
   if(exp < 3 || exp % 2 == 0)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   e = exp;

   do
      {
      p = random_prime(rng, (bits + 1) / 2, e);
      q = random_prime(rng, bits - p.bits(), e);
      n = p * q;
      } while(n.bits() != bits);

   d = inverse_mod(e, lcm(p - 1, q - 1));
   d1 = d % (p - 1);
   d2 = d % (q - 1);
   c = inverse_mod(q, p);

   gen_check(rng);
   }

/*
* Check Private RSA Parameters
*/
bool RSA_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!IF_Scheme_PrivateKey::check_key(rng, strong))
      return false;

   if(!strong)
      return true;

   if((e * d) % lcm(p - 1, q - 1) != 1)
      return false;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA4(SHA-1)");
   }

RSA_Private_Operation::RSA_Private_Operation(const RSA_PrivateKey& rsa) :
   n(rsa.get_n()),
   q(rsa.get_q()),
   c(rsa.get_c()),
   powermod_e_n(rsa.get_e(), rsa.get_n()),
   powermod_d1_p(rsa.get_d1(), rsa.get_p()),
   powermod_d2_q(rsa.get_d2(), rsa.get_q()),
   mod_p(rsa.get_p())
   {
   BigInt k(global_state().global_rng(), n.bits() - 1);
   blinder = Blinder(powermod_e_n(k), inverse_mod(k, n), n);
   }

BigInt RSA_Private_Operation::private_op(const BigInt& m) const
   {
   if(m >= n)
      throw Invalid_Argument("RSA private op - input is too large");

   BigInt j1 = powermod_d1_p(m);
   BigInt j2 = powermod_d2_q(m);

   j1 = mod_p.reduce(sub_mul(j1, j2, c));

   return mul_add(j1, q, j2);
   }

SecureVector<byte>
RSA_Private_Operation::sign(const byte msg[], u32bit msg_len,
                            RandomNumberGenerator&)
   {
   /* We don't check signatures against powermod_e_n here because
      PK_Signer checks verification consistency for all signature
      algorithms.
   */

   BigInt m(msg, msg_len);
   BigInt x = blinder.unblind(private_op(blinder.blind(m)));
   return BigInt::encode_1363(x, n.bytes());
   }

/*
* RSA Decryption Operation
*/
SecureVector<byte>
RSA_Private_Operation::decrypt(const byte msg[], u32bit msg_len)
   {
   BigInt m(msg, msg_len);
   BigInt x = blinder.unblind(private_op(blinder.blind(m)));

   if(m != powermod_e_n(x))
      throw Internal_Error("RSA private op failed consistency check");

   return BigInt::encode(x);
   }

}
