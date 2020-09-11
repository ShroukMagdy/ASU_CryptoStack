 #ifndef TESTS_H
 #define TESTS_H

#include "Csm.h"
#include "testUart.h"
#include "uart1.h"
#include "HASLCD_JR.h"
#include "HAS_Keypad_Password.h"
#include <string.h>


void testSH1 (void);
void testSH224 (void);
void testSH256 (void);
void testSH384 (void);
void testSH512 (void);
void testMD5(void);
void RNG(void);
void test3Des(void);
void testAes(void);
void testHmacG_Sh1(void);
void testCmacG_AES(void);
void testHmacV_Sh1(void);
void testCmacV_AES(void);
void testall(void);
void testall_rec();
#endif
