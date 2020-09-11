/*
 * sha_1.h
 *
 *  Created on: Mar 3, 2020
 *      Author: Ahmed Antar
 */

#ifndef SHA_1_H_
#define SHA_1_H_

/*************************** HEADER FILES ***************************/

#include "Platform_Types.h"
/****************************** MACROS ******************************/
#define SHA1_BLOCK_SIZE 20              // SHA1 outputs a 20 byte digest


typedef struct {
	uint8 data[64];
	uint32 datalen;
  uint64 bitlen;
	uint32 state[5];
	uint32 k[4];
} SHA1_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha1_init(SHA1_CTX *ctx);
void sha1_transform(SHA1_CTX *ctx, const uint8 data[]);
void sha1_update(SHA1_CTX *ctx, const uint8 data[], uint32 len);
void sha1_final(SHA1_CTX *ctx, uint8 hash[]);



#endif /* SHA_1_H_ */
