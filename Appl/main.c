#include "tests.h"
#include "Crypto.h"
#include "CryIf.h"

int main(){

    CryIf_Init();
    Crypto_Init();
    Csm_Init();

    testall();
  //testall_rec();

/*
     testSH1();
     testSH224();
     testSH256();
     testSH384();
     testSH512();
     testMD5();
     RNG();
*/

/*
     testAes();
     test3Des();
*/

/*
    testHmacG_Sh1();
    testCmacG_AES();
    testCmacV_AES();
    testHmacV_Sh1();
*/
        return 0;

}


