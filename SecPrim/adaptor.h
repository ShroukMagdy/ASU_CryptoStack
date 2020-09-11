 #ifndef ADAPTOR_H
 #define ADAPTOR_H
 
#include "SHA224.h"
#include "MD5.h"
#include "SHA1.h"
#include "SHA256.h"
#include "DES.h"
#include "AES_Enc.h" 
#include "AES_Dec.h" 
#include "pcg_basic.h"
#include "HMAC_SHA1.h"
#include "CMAC_AES.h"
#include "SHA384-512.h"

#define Triple_Des_KEY_SIZE 24
#define CMAC_AES_KEY_SIZE 16
#define AES_KEY_SIZE_1 16
#define AES_KEY_SIZE_2 24
#define AES_KEY_SIZE_3 32

void AlgoSHA1_adaptor( const uint8 data[],uint32 len,uint8 * hash);
void AlgoSHA224_adaptor( const uint8 data[],uint32 len,uint8* hash);
void AlgoSHA256_adaptor( const uint8 data[],uint32 len,uint8* hash);
void AlgoSHA384_adaptor( const uint8 data[],uint32 len,uint8 * hash);
void AlgoSHA512_adaptor( const uint8 data[],uint32 len,uint8 * hash);
void AlgoMD5_adaptor( const uint8 data[],uint32 len,uint8 * hash);
void Algo3DESEn_adaptor( const uint8 data[],uint32 len,uint8* outptr ,uint8 key[],uint32 StartByte ,uint32 ivstart);
void Algo3DESDe_adaptor( const uint8 data[],uint32 len,uint8* outptr ,uint8 key[],uint32 StartByte ,uint32 ivstart);
void Get_SEED (const uint8* seedPtr, uint32 seedLength); // 2 stuff
void Algo32RNG_adaptor( uint8* result,uint32*resLength,uint8* seed ,uint32 seedStartIndex);
void Algo_AesEn(const uint8 data[],uint32 len,uint8* outptr,uint8 key [],uint32 StartByte ,uint32 keyLen,uint32 ivstart) ;
void Algo_AesDe(const uint8 data[],uint32 len,uint8* outptr,uint8 key [],uint32 StartByte ,uint32 keyLen ,uint32 ivstart );
void Algo_HMAC_SHA1_adaptor(const uint8 data[],uint32 len,uint8* outptr,uint8 key [],uint32 StartByte ,uint32 keyLen );
void Algo_CMAC_AES_adaptor(const uint8 data[],uint32 len,uint8* outptr,uint8 key [],uint32 StartByte ,uint32 keyLen );
 
 
 
 
 
#endif
