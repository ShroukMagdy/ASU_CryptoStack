#include "tests.h"
#include "Crypto.h" //remove this one later
void RNG(){




uint32 	jobId =12;

static uint32 k=8;

 static uint8 RanArr[8] ={0};
  static  uint8 hh [16] ={0x4E,0xA3,0x77,0x99,0x10,0x89,0x60,0x90,0x36,0x10,0x22,0x90,0x99,0x40,0x33,0x00}   ;
  //static  uint8 h [16] ={};

  Csm_RandomSeed(1,hh ,16);
  //Csm_KeyElementGet(1,3,h ,&e);
  Csm_KeySetValid(1);
 Csm_RandomGenerate(jobId,RanArr,&k);
 /*
  * RNG+DES
 static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
  // static uint32 jobId =6;
  static uint32 a=40; //size of output
 static  uint32* e=&a;


 static const uint8 key []={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                            0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA
 };

static const uint8 ip []= {0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa
     ,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,0xbb,
     0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,0xcc,
      0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,0xEE,
      0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD,0xDD
                           };

     static  uint8 res[40] ={0} ;
      static  uint8 re[40] ={0} ;
      Std_ReturnType b= Csm_KeyElementSet(2,1,key,24);
      Std_ReturnType opl= Csm_KeyElementSet(2,5,RanArr,8);
       Std_ReturnType c=Csm_Encrypt(6,mode,ip, sizeof(ip),res,&a);
       Std_ReturnType f= Csm_KeyElementSet(2,1,key,24);
       Std_ReturnType op= Csm_KeyElementSet(2,5,RanArr,8);
       Std_ReturnType bl= Csm_KeyElementGet(2,5,re,24);
       Std_ReturnType d=Csm_Decrypt(10,mode,res, sizeof(res),re,&a);



*/
/*result
 *
 * b1 aa 7e 22 05 25 04 d0 c2 2e 15 76 f2 36 6D 34
 */


};
