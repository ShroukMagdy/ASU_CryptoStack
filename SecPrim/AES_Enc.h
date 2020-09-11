 #ifndef AES_ENC_H
 #define AES_ENC_H


#include "Platform_Types.h"

#define AES_BLOCK_SIZE 16               // AES outputs a 16 byte

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4




void encrypt_AES(uint8 in[],uint32 data_len,uint8 out[] ,uint8 keyData[],uint32 keyLen);

#endif
