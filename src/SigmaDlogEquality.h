#ifndef SIGMAPROTOCOL_SIGMADLOGEQUALITY_H
#define SIGMAPROTOCOL_SIGMADLOGEQUALITY_H

#include "SigmaProtocol.h"

namespace yacl::crypto {

class DlogEqualityCommonInput : public SigmaProtocolCommonInput {
 public:
  // G, H are generators of group
  DlogEqualityCommonInput(const EC_GROUP* group, EC_POINT* G1, EC_POINT* G2,
                          EC_POINT* H1, EC_POINT* H2,
                          const char* hashname = "sha256")
      : SigmaProtocolCommonInput(group, 2, 2, hashname) {
    this->G[0] = G1;
    this->G[1] = G2;
    this->H[0] = H1;
    this->H[1] = H2;
  }
};

class DlogEqualityProverShort : public SigmaProtocolProverShort {
 public:
  DlogEqualityProverShort(const DlogEqualityCommonInput& params,
                          const BIGNUM* x)
      : params_(params), SigmaProtocolProverShort() {
    GetK().emplace_back(BN_new());
    GetX().emplace_back(x);
    GetMsgReference().s.emplace_back(BN_new());
  }
  void Prove() override;

 private:
  const DlogEqualityCommonInput& params_;
};

class DlogEqualityProverBatch : public SigmaProtocolProverBatch {
 public:
  DlogEqualityProverBatch(const DlogEqualityCommonInput& params,
                          const BIGNUM* x)
      : params_(params), SigmaProtocolProverBatch(params.group) {
    GetK().emplace_back(BN_new());
    GetX().emplace_back(x);
    GetMsgReference().T.emplace_back(2, EC_POINT_new(params_.group));
    GetMsgReference().s.emplace_back(BN_new());
  }
  void Prove() override;

 private:
  const DlogEqualityCommonInput& params_;
};

class DlogEqualityVerifierShort : public SigmaProtocolVerifierShort {
 public:
  DlogEqualityVerifierShort(const DlogEqualityCommonInput& params,
                            const SigmaProtocolResponseMsgShort& msg)
      : params_(params), SigmaProtocolVerifierShort(msg) {}

  bool Verify() override;

 private:
  const DlogEqualityCommonInput& params_;
};

class DlogEqualityVerifierBatch : public SigmaProtocolVerifierBatch {
 public:
  DlogEqualityVerifierBatch(const DlogEqualityCommonInput& params,
                            const SigmaProtocolResponseMsgBatch& msg)
      : params_(params), SigmaProtocolVerifierBatch(msg) {}

  bool Verify() override;

 private:
  const DlogEqualityCommonInput& params_;
};

BIGNUM* DlogEqualityGetChallenge(const DlogEqualityCommonInput& params,
                                 const std::vector<EC_POINT*> T, BN_CTX* ctx);

}  // namespace yacl::crypto

#include "SigmaDlogEquality.cc"
#endif  // SIGMAPROTOCOL_SIGMADLOGEQUALITY_H
