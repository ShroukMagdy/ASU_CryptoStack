
#ifndef SHA384_512_H
#define SHA384_512_H

#include "Platform_Types.h"

#define SHA384_DIGEST_SIZE ( 384 / 8)
#define SHA512_DIGEST_SIZE ( 512 / 8)

#define SHA512_BLOCK_SIZE  (1024 / 8)
#define SHA384_BLOCK_SIZE  SHA512_BLOCK_SIZE







typedef struct {
    uint32 tot_len;
    uint32 len;
    uint8 block[2 * SHA512_BLOCK_SIZE];
    uint64 h[8];
} sha512_ctx;

typedef sha512_ctx sha384_ctx;



void sha384_init(sha384_ctx *ctx);
void sha384_update(sha384_ctx *ctx, const uint8 *message,
                   uint32 len);
void sha384_final(sha384_ctx *ctx, uint8 *digest);
void sha384(const uint8 *message, uint32 len,
            uint8 *digest);

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const uint8 *message,
                   uint32 len);
void sha512_final(sha512_ctx *ctx, uint8 *digest);
void sha512(const uint8 *message, uint32 len,
            uint8 *digest);



#endif /* !SHA384_512_H */

