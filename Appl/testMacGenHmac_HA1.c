#include "tests.h"
#include "Crypto.h"

void testHmacG_Sh1(void){

/*
    static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;

    static uint32 jobId =13;

    const uint8 plaintext[]=
"Ashortstoryisapieceofprosefictionthattypicallycanbereadinonesittingandfocusesona";

    uint32 length=80;
      uint8 key[]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                          0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
                          0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
                          0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f};

                uint32 key_length=64;
                uint8 dig[64]={0};
                  uint8 digest[20]={0};
                 uint32 digest_length=20;
                 uint32* digest_length_ptr=&digest_length;
                 Csm_KeyElementSet(6,1,key,key_length);
                 Csm_KeySetValid(6);
                 Csm_KeyElementGet(6,1,dig,&key_length);
                 Csm_MacGenerate( jobId,mode,plaintext,length,digest, digest_length_ptr);

*/


    /*
    uint32 jobId =14;
    const  uint8 plaintext[]={0x48,0x69,0x20,0x54,0x68,0x65,0x72,0x65};
       uint32 length=8;
       uint8 key[]={0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                    0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
                    0x0b,0x0b,0x0b,0x0b};
       uint32 key_length=20;
       uint8 digest[20]={0};
       uint32 digest_length=20;
       uint32* digest_length_ptr=&digest_length;

       Csm_KeyElementSet(7,1,key,key_length);
       Csm_KeySetValid(7);
     ;
       Csm_MacGenerate( jobId,mode,plaintext,length,digest, digest_length_ptr);
               //Digest = b6 17 31 86 55 05 72 64 e2 8b c0 b6 fb 37 8c 8e f1 46 be 00


*/
    /*
    uint32 jobId =14;
    const static uint8 plaintext[]={0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
         0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
         0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
         0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,
     0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd,0xdd};
     uint32 length=50;
     uint8 key[]={0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
       uint32 key_length=20;

       uint8 digest[20]={0};
             uint32 digest_length=20;
             uint32* digest_length_ptr=&digest_length;
             Csm_KeyElementSet(7,1,key,key_length);
             Csm_KeySetValid(7);
             Csm_MacGenerate( jobId,mode,plaintext,length,digest, digest_length_ptr);


}
// Digest = 12 5d 73 42 b9 ac 11 cd 91 a3 9a f4 8a a1 7b 4f 63 f1 75 d3
  */
    /*
    uint32 jobId =15;
    const uint8 plaintext[]={0x54,0x65,0x73,0x74,0x20,0x55,0x73,0x69,0x6e,0x67,0x20,0x4c,0x61,0x72,0x67,0x65,
         0x72,0x20,0x54,0x68,0x61,0x6e,0x20,0x42,0x6c,0x6f,0x63,0x6b,0x2d,0x53,0x69,0x7a,
         0x65,0x20,0x4b,0x65,0x79,0x20,0x61,0x6e,0x64,0x20,0x4c,0x61,0x72,0x67,0x65,0x72,
         0x20,0x54,0x68,0x61,0x6e,0x20,0x4f,0x6e,0x65,0x20,0x42,0x6c,0x6f,0x63,0x6b,0x2d,
         0x53,0x69,0x7a,0x65,0x20,0x44,0x61,0x74,0x61};
     uint32 length=73;
     uint8 key[]={0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
     uint32 key_length=80;


         uint8 digest[20]={0};
         uint32 digest_length=20;
         uint32* digest_length_ptr=&digest_length;
         Csm_KeyElementSet(8,1,key,key_length);
         Csm_KeySetValid(8);
         Csm_MacGenerate( jobId,mode,plaintext,length,digest, digest_length_ptr);

         //Digest = e8 e9 9d 0f 45 23 7d 78 6d 6b ba a7 96 5c 78 08 bb ff 1a 91

          */
    static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    uint32 jobId =15;
    const static uint8 plaintext[]={0x54,0x65,0x73,0x74,0x20,0x55,0x73,0x69,0x6e,0x67,0x20,
                                    0x4c,0x61,0x72,0x67,0x65,
         0x72,0x20,0x54,0x68,0x61,0x6e,0x20,0x42,0x6c,0x6f,0x63,0x6b,0x2d,0x53,0x69,0x7a,
         0x65,0x20,0x4b,0x65,0x79,0x20,0x2d,0x20,0x48,0x61,0x73,0x68,0x20,0x4b,0x65,0x79,
         0x20,0x46,0x69,0x72,0x73,0x74};
     uint32 length=54;
     uint8 key[]={0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,
         0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa};
         uint32 key_length=80;

         uint8 digest[20]={0};
         uint32 digest_length=20;
         uint32* digest_length_ptr=&digest_length;
         Csm_KeyElementSet(8,1,key,key_length);
         Csm_KeySetValid(8);
         Csm_MacGenerate( jobId,mode,plaintext,length,digest, digest_length_ptr);


         //Digest = aa 4a e5 e1 52 72 d0 0e 95 70 56 37 ce 8a 3b 55 ed 40 21 12








}
