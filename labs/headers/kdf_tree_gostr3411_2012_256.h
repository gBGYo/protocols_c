#ifndef KDF_TREE_GOSTR3411_2012_256_H
#define KDF_TREE_GOSTR3411_2012_256_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/random.h>

    void kdf_tree_gostr3411_2012_256(
        const uint8_t *key,
        size_t key_len,
        const uint8_t *label,
        size_t label_len,
        const uint8_t *seed,
        size_t seed_len,
        size_t R,
        uint8_t *derived_key,
        size_t derived_key_len);

#ifdef __cplusplus
}
#endif

#endif /* KDF_TREE_GOSTR3411_2012_256_H */