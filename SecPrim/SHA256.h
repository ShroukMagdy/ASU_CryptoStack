

#ifndef SHA256_H_
#define SHA256_H_

/*************************** HEADER FILES ***************************/
#include "Platform_Types.h"

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/

typedef struct {
	uint8 data[64];
	uint32 datalen;
  uint64 bitlen;
	uint32 state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8 data[], uint32 len);
void sha256_final(SHA256_CTX *ctx, uint8 hash[]);
void sha256( const uint8  data[],uint32 len,uint8 * hash,SHA256_CTX *ctx);

#endif /* SHA256_H_ */
