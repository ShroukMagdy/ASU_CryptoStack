
#include "Platform_Types.h"
#define DES_Enc_BLOCK_SIZE 8               // DES outputs a 8 byte


uint64 encrypt_DES(uint64 input, uint64 key[],uint64 result);
uint64 decrypt_DES(uint64 input, uint64 key[] ,uint64 result);
