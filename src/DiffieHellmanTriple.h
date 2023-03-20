#ifndef SIGMAPROTOCOL_DIFFIEHELLMANTRIPLE_H
#define SIGMAPROTOCOL_DIFFIEHELLMANTRIPLE_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include "SigmaProtocol.h"

// Relation R of Diffie-Hellman triple: (H1,H2,H3), Prover wants to prove that
// H1 = x1*G, H2 = x2*G, H3 = (x1x2)*G, the required multiplicative relation can
// be proven by observing that the proof goal is equivalent to H1 = x1*G,
// H2 = x2*G and H3 = x2*H1

namespace yacl::crypto {

struct DiffieHellmanTripleCommonInput : public SigmaProtocolCommonInput {
 public:
  DiffieHellmanTripleCommonInput(const EC_GROUP* group, const EC_POINT* G,
                                 const EC_POINT* H1, const EC_POINT* H2,
                                 const EC_POINT* H3,
                                 const char* hashname = "sha256")
      : SigmaProtocolCommonInput(group, 1, 3, hashname) {
    this->G[0] = G;
    this->H[0] = H1;
    this->H[1] = H2;
    this->H[2] = H3;
  }
};

class DiffieHellmanTripleProverShort : public SigmaProtocolProverShort {
 public:
  DiffieHellmanTripleProverShort(const DiffieHellmanTripleCommonInput& params,
                                 const BIGNUM* x1, const BIGNUM* x2)
      : params_(params), SigmaProtocolProverShort() {
    GetK().emplace_back(2, BN_new());
    GetX().emplace_back(x1);
    GetX().emplace_back(x2);
    GetMsgReference().s.emplace_back(2, BN_new());
  }

  void Prove() override;

 private:
  const DiffieHellmanTripleCommonInput& params_;
};

class DiffieHellmanTripleProverBatch : public SigmaProtocolProverBatch {
 public:
  DiffieHellmanTripleProverBatch(const DiffieHellmanTripleCommonInput& params,
                                 const BIGNUM* x1, const BIGNUM* x2)
      : params_(params), SigmaProtocolProverBatch(params_.group) {
    GetK().emplace_back(2, BN_new());
    GetX().emplace_back(x1);
    GetX().emplace_back(x2);
    GetMsgReference().s.emplace_back(2, BN_new());
    GetMsgReference().T.emplace_back(3, EC_POINT_new(params_.group));
  }

  void Prove() override;

 private:
  const DiffieHellmanTripleCommonInput& params_;
};

class DiffieHellmanTripleVerifierShort : public SigmaProtocolVerifierShort {
 public:
  DiffieHellmanTripleVerifierShort(
      const DiffieHellmanTripleCommonInput& params_,
      const SigmaProtocolResponseMsgShort& msg)
      : params_(params_), SigmaProtocolVerifierShort(msg) {}

  bool Verify() override;

 private:
  const DiffieHellmanTripleCommonInput& params_;
};

class DiffieHellmanTripleVerifierBatch : public SigmaProtocolVerifierBatch {
 public:
  DiffieHellmanTripleVerifierBatch(
      const DiffieHellmanTripleCommonInput& params_,
      const SigmaProtocolResponseMsgBatch& msg)
      : params_(params_), SigmaProtocolVerifierBatch(msg) {}

  bool Verify() override;

 private:
  const DiffieHellmanTripleCommonInput& params_;
};

BIGNUM* DiffieHellmanTripleGetChallenge(
    const DiffieHellmanTripleCommonInput& params_,
    const std::vector<EC_POINT*>& T, BN_CTX* ctx);

}  // namespace yacl::crypto

#endif  // SIGMAPROTOCOL_DIFFIEHELLMANTRIPLE_H
