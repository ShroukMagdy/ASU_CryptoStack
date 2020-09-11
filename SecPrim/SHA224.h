
#ifndef SHA224_H_
#define SHA224_H_

/*************************** HEADER FILES ***************************/
#include "Platform_Types.h"
/****************************** MACROS ******************************/
#define SHA224_BLOCK_SIZE 28            // SHA224 outputs a 28 byte digest

/**************************** DATA TYPES ****************************/

typedef struct {
	uint8 data[64];
	uint32 datalen;
	uint64 bitlen;
	uint32 state[8];
} SHA224_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha224_init(SHA224_CTX *ctx);
void sha224_update(SHA224_CTX *ctx, const uint8 data[], uint32 len);
void sha224_final(SHA224_CTX *ctx, uint8 hash[]);






#endif /* SHA224_H_ */
