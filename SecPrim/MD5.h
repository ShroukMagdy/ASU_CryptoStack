

#ifndef MD5_H_
#define MD5_H_

/*************************** HEADER FILES ***************************/
#include "Platform_Types.h"

/****************************** MACROS ******************************/
#define MD5_BLOCK_SIZE 16               // MD5 outputs a 16 byte digest

/**************************** DATA TYPES ****************************/


typedef struct {
   uint8 data[64];
   uint32 datalen;
   uint64 bitlen;
   uint32 state[4];
} MD5_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const uint8 data[], uint32 len);
void md5_final(MD5_CTX *ctx, uint8 hash[]);




#endif /* MD5_H_ */
