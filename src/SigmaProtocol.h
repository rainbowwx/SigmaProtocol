#ifndef SIGMAPROTOCOL_SIGMAPROTOCOL_H
#define SIGMAPROTOCOL_SIGMAPROTOCOL_H

// Implement UGZK protocol:
// let n be a positive integer and let i \in [1,n]. For a given vector {Z_i}_{i
// \in [1,n]}, the protocol is a proof of knowledge of a vector {[x_i]}_{i \in
// [1,n]} such that Z_i = [x_i]

#pragma once

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <vector>

#include "hash.h"

namespace yacl::crypto {
// SigmaprotocolCommoInput specifies the OneWayHomomorphism and hashname of
// practical protocol
struct SigmaProtocolCommonInput {
  SigmaProtocolCommonInput(const EC_GROUP* group, size_t n,
                           const char* hashname)
      : group(group), n(n), hashname(hashname), H(n, nullptr), G(n, nullptr) {
    p = EC_GROUP_get0_order(group);
  }

  const EC_GROUP* group;
  const BIGNUM* p;
  size_t n;                        // element number of vector G
  std::vector<const EC_POINT*> H;  // the public group elements
  std::vector<const EC_POINT*> G;  // the public generators of group
  const char* hashname;
};

struct SigmaProtocolResponseMsgShort {
  BIGNUM* s;  // The second message which prover computed
  BIGNUM* c;  // challenge
  SigmaProtocolResponseMsgShort() {
    s = BN_new();
    c = BN_new();
  }

  SigmaProtocolResponseMsgShort(BIGNUM* s, BIGNUM* c) {
    s = BN_new();
    c = BN_new();
    BN_copy(this->s, s);
    BN_copy(this->c, c);
  }

  SigmaProtocolResponseMsgShort(const SigmaProtocolResponseMsgShort& msg) {
    s = BN_new();
    c = BN_new();
    BN_copy(this->s, msg.s);
    BN_copy(this->c, msg.c);
  }

  ~SigmaProtocolResponseMsgShort() {
    BN_free(s);
    BN_free(c);
  }
};

struct SigmaProtocolResponseMsgBatch {
  const EC_GROUP* group;
  EC_POINT* T;
  BIGNUM* s;

  SigmaProtocolResponseMsgBatch(const EC_GROUP* group) {
    this->group = group;
    T = EC_POINT_new(this->group);
    s = BN_new();
  }

  SigmaProtocolResponseMsgBatch(const EC_GROUP* group, const EC_POINT* T,
                                const BIGNUM* r) {
    this->group = group;
    T = EC_POINT_new(this->group);
    r = BN_new();
    EC_POINT_copy(this->T, T);
    BN_copy(this->s, r);
  }

  SigmaProtocolResponseMsgBatch(const SigmaProtocolResponseMsgBatch& msg) {
    this->group = msg.group;
    T = EC_POINT_new(this->group);
    s = BN_new();
    EC_POINT_copy(this->T, msg.T);
    BN_copy(this->s, msg.s);
  }

  ~SigmaProtocolResponseMsgBatch() {
    EC_POINT_free(T);
    BN_free(s);
  }
};

// SigmaProtocolProver wants to prove that he/she knows {x_i}_{i \in [1,n]}
// which satisfy {Z_i}_{i \in [1,n]} = {[x_i]}_{i \in [1,n]}
class SigmaProtocolProverShort {
 public:
  SigmaProtocolProverShort() : msg_() {}

  virtual ~SigmaProtocolProverShort(){};

  virtual void Prove() = 0;

  std::vector<const BIGNUM*>& GetX() { return this->x_; }

  std::vector<BIGNUM*>& GetK() { return this->k_; }

  SigmaProtocolResponseMsgShort GetMsg() { return this->msg_; }

 protected:
  SigmaProtocolResponseMsgShort& GetMsgReference() { return this->msg_; }

 private:
  std::vector<const BIGNUM*> x_;  // witness vector
  std::vector<BIGNUM*> k_;        // random elements take from group G

  SigmaProtocolResponseMsgShort msg_;
};

// This class
class SigmaProtocolProverBatch {
 public:
  SigmaProtocolProverBatch(const EC_GROUP* group) : msg_(group) {}

  virtual ~SigmaProtocolProverBatch(){};

  virtual void Prove() = 0;

  std::vector<const BIGNUM*>& GetX() { return this->x_; }

  std::vector<BIGNUM*>& GetK() { return this->k_; }

  SigmaProtocolResponseMsgBatch GetMsg() { return this->msg_; }

 protected:
  SigmaProtocolResponseMsgBatch& GetMsgReference() { return this->msg_; }

 private:
  std::vector<const BIGNUM*> x_;  // witness vector
  std::vector<BIGNUM*> k_;        // random elements take from group G

  SigmaProtocolResponseMsgBatch msg_;
};

class SigmaProtocolVerifierShort {
 public:
  SigmaProtocolVerifierShort(const SigmaProtocolResponseMsgShort& msg)
      : msg_(msg) {}

  virtual bool Verify() = 0;

  SigmaProtocolResponseMsgShort& GetMsg() { return this->msg_; }

  virtual ~SigmaProtocolVerifierShort(){};

 private:
  SigmaProtocolResponseMsgShort msg_;
};

class SigmaProtocolVerifierBatch {
 public:
  SigmaProtocolVerifierBatch(const SigmaProtocolResponseMsgBatch& msg)
      : msg_(msg) {}

  virtual bool Verify() = 0;

  SigmaProtocolResponseMsgBatch& GetMsg() { return this->msg_; }

  virtual ~SigmaProtocolVerifierBatch(){};

 private:
  SigmaProtocolResponseMsgBatch msg_;
};

}  // namespace yacl::crypto

#endif  // SIGMAPROTOCOL_SIGMAPROTOCOL_H
