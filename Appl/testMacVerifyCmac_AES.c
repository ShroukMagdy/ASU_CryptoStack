#include "tests.h"
#include "Crypto.h"

void testCmacV_AES(void){


    static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    static uint32 jobId =19;

    Crypto_VerifyResultType verify =CRYPTO_E_VER_NOT_OK;
    Crypto_VerifyResultType *verifyPtr = &verify;
     uint8 key[16] = {
                                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
        };

     const  uint8 data[] = {
                           0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                           0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};

     const uint8 mac[]= {//0xdf,0xa6,0x67,0x47,0xde,0x9a,0xe6,0x30,0x30,0xca,0x32,0x61,0x14,0x97,0xc8,0x27
                        0x07,0x0a,0x16,0xb4,0x6b,0x4d,0x41,0x44,0xf7,0x9b,0xdd,0x9d,0xd0,0x4a,0x28,0x7c
                        };
                      //result 070a16b4 6b4d4144 f79bdd9d d04a287c
/*
    static uint8 data[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11
                    };
    //result 0xdf,0xa6,0x67,0x47,0xde,0x9a,0xe6,0x30,x30,0xca,0x32,0x61,0x14,0x97,0xc8,0x 27

*/

    static  uint8 ik_enc [16]= {0};
    static uint32 j_enc=16;

    Std_ReturnType l_enc= Csm_KeyElementSet(3,1,key,j_enc);
    Csm_KeySetValid(3);
    Std_ReturnType p_enc= Csm_KeyElementGet(3,1,ik_enc,&j_enc);
    Csm_MacVerify( jobId,mode,data,sizeof(data),mac,sizeof(mac),verifyPtr);

}
