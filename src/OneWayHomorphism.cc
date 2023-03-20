#include "OneWayHomomorphism.h"

namespace yacl::crypto {
void OneWayHomomorphism(const EC_GROUP* group, const EC_POINT* input,
                        const EC_POINT* G, EC_POINT* output) {}

void OneWayHomomorphisms(const EC_GROUP* group, const EC_POINT* input,
                         int index, EC_POINT* output) {}
}  // namespace yacl::crypto
