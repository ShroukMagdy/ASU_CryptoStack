#include "tests.h"

void testAes(void){



/*
    static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;

  //  test 128
    static uint32 jobId_enc =7;




  static const uint8 key_enc []={
                             0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                             0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF


  };

 static const uint8 ip_enc []=
"Ashortstoryisapieceofprosefictionthattypicallycanbereadinonesittingandfocusesona";

 static const uint8 iv_enc []= {0x7a,0x2e,0xa5,0x54,0x66,0xba,0x64,0x8b,0x05,0x1b,0x7f,0xcd,0x7a,0x33,0x62,0xec};
       static  uint8 ik_enc [16]= {0};
       static uint32 j_enc=16;
      static  uint8 res_enc[80] ={0};
      static  uint8 res_Dec[80] ={0};
      uint32 ipL_enc =64;

      Std_ReturnType l_enc= Csm_KeyElementSet(3,1,key_enc,j_enc);
       Csm_KeySetValid(3);
      Std_ReturnType p_enc= Csm_KeyElementGet(3,1,ik_enc,&j_enc);
      Std_ReturnType op_enc= Csm_KeyElementSet(3,5,iv_enc,16);
       Csm_KeySetValid(3);
      Std_ReturnType c_enc=Csm_Encrypt(jobId_enc,mode,ip_enc, sizeof(ip_enc),res_enc,&ipL_enc);
      Std_ReturnType c_Dec=Csm_Decrypt(18,mode,res_enc, sizeof(ip_enc),res_Dec,&ipL_enc);
*/

/*

       // test 192
    static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
     static uint32 jobId =8;
      const uint8 key []={
                             0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                             0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,


  };

         const uint8 ip []=
 "Ashortstoryisapieceofprosefictionthattypicallycanbereadinonesittingandfocusesona";

    uint8 Dec_res[80] ={0} ;
    uint8 res[80] ={0} ;
    static  uint8 ik [24]= {0};
    static uint32 j=24;
    uint32 ipL=608;
  static const uint8 iv []= {0x7a,0x2e,0xa5,0x54,0x66,0xba,0x64,0x8b,0x05,0x1b,
                             0x7f,0xcd,0x7a,0x33,0x62,0xec};
  Std_ReturnType b= Csm_KeyElementSet(4,1,key,24);
        Csm_KeySetValid(4);
       Std_ReturnType l= Csm_KeyElementGet(4,1,ik,&j);
       Std_ReturnType op= Csm_KeyElementSet(4,5,iv,16);
        Csm_KeySetValid(4);
      Std_ReturnType c=Csm_Encrypt(jobId,mode,ip,608,res,&ipL);
        Csm_Decrypt(20,mode,res,sizeof(res),Dec_res,&ipL);//same ip

    */
   //   test 256
    static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
   static uint32 jobId =9;
           static const uint8 key []={
                                      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                                      0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
                                       0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF


     };

  const uint8 ip []=
  "Ashortstoryisapieceofprosefictionthattypicallycanbereadinonesittingandfocusesona";

           uint8 res[80] ={0} ;
           uint8 Dec_res[80] ={0} ;
           static  uint8 ik [32]= {0};
          static uint32 j=32;
          uint32 ipL=80;
  static const uint8 iv []= {0x7a,0x2e,0xa5,0x54,0x66,0xba,0x64,0x8b,
                             0x05,0x1b,0x7f,0xcd,0x7a,0x33,0x62,0xec};
          Std_ReturnType b= Csm_KeyElementSet(5,1,key,32);
          Csm_KeySetValid(5);
          Std_ReturnType l= Csm_KeyElementGet(5,1,ik,&j);
          Std_ReturnType op= Csm_KeyElementSet(5,5,iv,16);
          Csm_KeySetValid(5);
         Std_ReturnType c=Csm_Encrypt(jobId,mode,ip,80,res,&ipL);
                 Csm_Decrypt(11,mode,res,sizeof(res), Dec_res,&ipL);


/*
    //  decryption

    static uint32 jobId_dec =11;
    static const uint8 key_dec []={


                               0x08,0x09,0x0A,0x0B,0x0D,0x0E,0x0F,0x10,
                               0x12,0x13,0x14,0x15,0x17,0x18
                               ,0x19,0x1A,0x1C,0x1D,0x1E,0x1F,0x21,0x22,0x23,0x24,0x26,0x27,0x28,0x29,0x2B,0x2C,0x2D,0x2E


    };

    static const uint8 ip_dec []= {0x06,0x9A,0x00,0x7F,0xC7,0x6A,0x45,0x9F,0x98,0xBA,0xF9,0x17,0xFE,0xDF,0x95,0x21,
                                   0x06,0x9A,0x00,0x7F,0xC7,0x6A,0x45,0x9F,0x98,0xBA,0xF9,0x17,0xFE,0xDF,0x95,0x21,
                                   0x7a,0x2e,0xa5,0x54,0x66,0xba,0x64,0x8b,0x05,0x1b,0x7f,0xcd,0x7a,0x33,0x62,0xec,
                                   0x06,0x9A,0x00,0x7F,0xC7,0x6A,0x45,0x9F,0x98,0xBA,0xF9,0x17,0xFE,0xDF,0x95,0x21
    };



    static  uint8 res_dec[64] ={0} ;
    static  uint8 ik_dec [32]= {0};
    static uint32 j_dec=32;
    static uint32 ipL_dec=64;
    static const uint8 iv []= {0x7a,0x2e,0xa5,0x54,0x66,0xba,0x64,0x8b,0x05,0x1b,0x7f,0xcd,0x7a,0x33,0x62,0xec};
    Std_ReturnType b_dec= Csm_KeyElementSet(5,1,key_dec,32);
    Csm_KeySetValid(5);
    Std_ReturnType l_dec= Csm_KeyElementGet(5,1,ik_dec,&j_dec);
    Std_ReturnType op= Csm_KeyElementSet(5,5,iv,16);
    Csm_KeySetValid(5);
    Std_ReturnType c_dec=Csm_Decrypt(jobId_dec,mode,ip_dec,64,res_dec,&ipL_dec);
    Csm_Encrypt(9,mode,res_dec,sizeof(res_dec),res_dec,&ipL_dec); //same input
    */
/*
   72   23  56  81  d6  61  25  89  c0  bd  6e  38  ff  5b  26  61
   0e  97  f3  aa  77  b1  04  9d  5d  1c  e8  e2  7b  b7  d1  ac
   12  eb  79  bd  f9  57  df  0a  66  46  46  61  00  4f  57  e8
   72  23  56  81  d6  61  25  89  c0  bd  6e  38  ff  5b  26  61

 */




}
