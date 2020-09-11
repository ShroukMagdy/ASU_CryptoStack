#include "DES.h"

#define LB32   0x00000001 //32 BT MASKELEME sol bit 32
#define LB64   0x0000000000000001 //64 BT MASKELEME sol bit 64
#define L64_MASK    0x00000000ffffffff   //SMETR sol bit simetri alma
#define H64_MASK    0xffffffff00000000	//SMETR son hal

/* Initial Permutation tablosu */
static uint8 IP[] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

/* Inverse Initial Permutation tablosu */
static uint8 PI[] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

/*Expansion tablosu */
static uint8 E[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

/* Post S-Box permutation */
static uint8 P[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

/* The S-Box tablosu */
static uint8 S[8][64] = {{
    /* S1 */
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
},{
    /* S2 */
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
},{
    /* S3 */
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
},{
    /* S4 */
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
},{
    /* S5 */
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
},{
    /* S6 */
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
},{
    /* S7 */
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
},{
    /* S8 */
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
}};

/* Permuted Choice 1 tablosu */
static uint8 PC1[] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,

    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

/* Permuted Choice 2 tablosu */
static uint8 PC2[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

/* Iteration Shift Array */
static uint8 iteration_shift[] = {
 /* 1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16 */
    1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1
};
static uint64 des(uint64 input, uint64 key,   uint8 mode);

uint64 des(uint64 input, uint64 key,   uint8 mode) {


    int i, j;

    /* 8 bit */
    uint8 satir, sutun;

    /* 28 bits */
    uint32 C                  = 0;
    uint32 D                  = 0;

    /* 32 bit */
    uint32 L                  = 0;
    uint32 R                  = 0;
    uint32 s_output           = 0;
    uint32 f_function_res     = 0;
    uint32 temp               = 0;

    /* 48 bit */
    uint64 sub_key[16]        = {0};
    uint64 s_input            = 0;

    /* 56 bit */
    uint64 permuted_choice_1  = 0;
    uint64 permuted_choice_2  = 0;

    /* 64 bit */
    uint64 init_perm_res      = 0;
    uint64 inv_init_perm_res  = 0;
    uint64 pre_output         = 0;

    /* initial permutation */
    for (i = 0; i < 64; i++) {

        init_perm_res <<= 1;//girilen deeri 1 bit yana
        init_perm_res |= (input >> (64-IP[i])) & LB64; //Initial Permutation tablosunda bit kaydrma yapp or  sokup
        //|=ilem ile tekrar or  girdi.



    }
  
    L = (uint32) (init_perm_res >> 32) & L64_MASK;//  64 biti 32 bit 32 bit.
  
    R = (uint32) init_perm_res & L64_MASK;  // sag taraf durcak
   
    /* initial key  */
    for (i = 0; i < 56; i++) {

        permuted_choice_1 <<= 1;//
        permuted_choice_1 |= (key >> (64-PC1[i])) & LB64;//64 bitten 56 bit
		 //printf ("ilk karistirma(anahtar): %llx\n", permuted_choice_1);
    }

    C = (uint32) ((permuted_choice_1 >> 28) & 0x000000000fffffff);// tablodaki bitler 28
    D = (uint32) (permuted_choice_1 & 0x000000000fffffff);//ve kontrol
 
    /* 16 tane anahtar olusturma*/
    for (i = 0; i< 16; i++) {


        // shift Ci and Di
        for (j = 0; j < iteration_shift[i]; j++) { //shift tablosundaki index

            C =( 0x0fffffff & (C << 1) ) | ( 0x00000001 & (C >> 27) );
            D = (0x0fffffff & (D << 1)  ) | ( 0x00000001 & (D >> 27) ) ;

        }
    //	printf ("%d:SOL 56 Bit(SHIFT): %llx\n",i,C);
     //	printf ("%d:SAG 56 Bit(SHIFT): %llx\n",i,D);

        permuted_choice_2 = 0;
        permuted_choice_2 = (((uint64) C) << 28) | (uint64) D ;

        sub_key[i] = 0;
        //48
        for (j = 0; j < 48; j++) {

            sub_key[i] <<= 1;//32+32
            sub_key[i] |= (permuted_choice_2 >> (56-PC2[j])) & LB64;

        }

    }



    for (i = 0; i < 16; i++) {


        s_input = 0;

        for (j = 0; j< 48; j++) {

            s_input <<= 1;
            s_input |= (uint64) ((R >> (32-E[j])) & LB32);

        }


		  if (mode == 'd') {
            //decryption
            s_input = s_input ^ sub_key[15-i];

        	} else {
            // encryption
            s_input = s_input ^ sub_key[i];

        	}


        for (j = 0; j < 8; j++) {


            satir = (uint8) ((s_input & (0x0000840000000000 >> 6*j)) >> (42-6*j));
            satir = (satir >> 4) | (satir & 0x01);

            sutun = (uint8) ((s_input & (0x0000780000000000 >> 6*j)) >> (43-6*j));

            s_output <<= 4;
            s_output |= (uint32) (S[j][16*satir + sutun] & 0x0f);

        }

        f_function_res = 0;

        for (j = 0; j < 32; j++) {

            f_function_res <<= 1;
            f_function_res |= (s_output >> (32 - P[j])) & LB32;

        }

        temp = R;
        R = L ^ f_function_res;
        L = temp;
        //printf ("%d:SAG: %llx  SOL: %llx\n",j, R,L);
    }

    pre_output = (((uint64) R) << 32) | (uint64) L;

    /* inverse initial permutation */
    for (i = 0; i < 64; i++) {

        inv_init_perm_res <<= 1;
        inv_init_perm_res |= (pre_output >> (64-PI[i])) & LB64;

    }

    return inv_init_perm_res;

}
uint64 encrypt_DES(uint64 input, uint64 key[] ,uint64 result){



     result = input;

    result = des(input, key[0], 'e');

    result = des(result, key[1], 'd');
    result = des(result, key[2], 'e');

		

		   return result;
}
uint64 decrypt_DES(uint64 input,uint64 key[],uint64 result){

    result = input;
    result = des(result, key[2], 'd');
    result = des(result, key[1], 'e');
    result = des(result, key[0], 'd');
		return result;
  

}
