#include "tests.h"

void test3Des(void){




   static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
    static uint32 jobId =6;
   static uint32 a=248; //size of output



  static const uint8 key []={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                             0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                             0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA
  };

 static const uint8 ip []=
"Ashortstoryisapieceofprosefictionthattypicallycanbereadinonesittingandfocusesona";
                            /*0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
      ,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
      0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
       0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
       0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD
                  */

       static const uint8 iv []= {0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d};
      static  uint8 res[80] ={0} ;
      static  uint8 re[80] ={0} ;
      Std_ReturnType b= Csm_KeyElementSet(2,1,key,24);
      Csm_KeySetValid(2);
      Std_ReturnType opl= Csm_KeyElementSet(2,5,iv,8);
      Csm_KeySetValid(2);
       Std_ReturnType c=Csm_Encrypt(jobId,mode,ip, sizeof(ip),res,&a);
       Std_ReturnType d=Csm_Decrypt(10,mode,res, sizeof(res),re,&a); //sameip



}
