#ifndef ONEWAYHOMOMORPHISM_H
#define ONEWAYHOMOMORPHISM_H

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdio>
#include <vector>
namespace yacl::crypto {

// This function calculate
void OneWayHomomorphism(const EC_GROUP* group, const EC_POINT* G,
                        const EC_POINT* input, EC_POINT* output);

void OneWayHomomorphisms(const EC_GROUP* group, const EC_POINT* input,
                         int index, EC_POINT* output);

}  // namespace yacl::crypto

#endif  // ONEWAYHOMOMORPHISM_H