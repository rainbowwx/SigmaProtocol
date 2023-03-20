#include "SigmaProtocol.h"

#include <cassert>
namespace yacl::crypto {
BIGNUM* SigmaProtocolGetChallenge(const SigmaProtocolCommonInput* params,
                                  const std::vector<const EC_POINT*> T,
                                  BN_CTX* ctx) {
  size_t n = params->G.size() + T.size();
  std::vector<unsigned char*> data(n);
  std::vector<unsigned int> length(n);
  BIGNUM* challenge = BN_new();
  for (size_t i = 0; i < params->G.size(); i++) {
    length.emplace_back((params->group, params->G[i],
                         POINT_CONVERSION_COMPRESSED, &data[i], ctx));
  }
  for (size_t i = 0; i < T.size(); i++) {
    length.emplace_back(
        (params->group, T[i], POINT_CONVERSION_COMPRESSED, &data[i], ctx));
  }
  unsigned char* md = nullptr;
  unsigned int md_length = 0;
  assert(HashEncode(params->hashname, data, length, md, md_length) == 0);

  BN_bin2bn(md, md_length, challenge);

  return challenge;
}

}  // namespace yacl::crypto