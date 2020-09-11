/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  HMAC_SHA1.c
 *        \brief  HMAC_SHA1 algorithm
 *
 *      \details  Implementation of the HMAC using sha1 algorithm
 *
 *********************************************************************************************************************/

/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/

#include "HMAC_SHA1.h"

/********************************************/
/* Test Cases                               */
/* An array of test cases taken from the    */
/* 802.11i specification.                   */
/********************************************/

/**********************************************************************************************************************
 *  LOCAL FUNCTION Definition
 *********************************************************************************************************************/

/****************************************/
/* sha1()                               */
/* Performs the NIST SHA-1 algorithm    */
/****************************************/


uint32 ft(
                    uint32 t,
                    uint32 x,
                    uint32 y,
                    uint32 z
                    )
{
uint32 a,b,c;

    if (t < 20)
    {
        a = x & y;
        b = (~x) & z;
        c = a ^ b;
    }
    else if (t < 40)
    {
        c = x ^ y ^ z;
    }
    else if (t < 60)
    {
        a = x & y;
        b = a ^ (x & z);
        c = b ^ (y & z);
    }
    else if (t < 80)
    {
        c = (x ^ y) ^ z;
    }

    return c;
}

uint32 k(uint32 t)
{
uint32 c;

    if (t < 20)
    {
        c = 0x5a827999;
    }
    else if (t < 40)
    {
        c = 0x6ed9eba1;
    }
    else if (t < 60)
    {
        c = 0x8f1bbcdc;
    }
    else if (t < 80)
    {
        c = 0xca62c1d6;
    }

    return c;
}

uint32 rotr(uint32 bits, uint32 a)
{
uint32 c,d,e,f,g;
    c = (0x0001 << bits)-1;
    d = ~c;

    e = (a & d) >> bits;
    f = (a & c) << (32 - bits);

    g = e | f;

    return (g & 0xffffffff );

}

uint32 rotl(uint32 bits, uint32 a)
{
uint32 c,d,e,f,g;
    c = (0x0001 << (32-bits))-1;
    d = ~c;

    e = (a & c) << bits;
    f = (a & d) >> (32 - bits);

    g = e | f;

    return (g & 0xffffffff );

}


void sha1   (
            uint8 *message,
            uint32 message_length,
            uint8 *digest
            )
{
uint32 i;
uint32 num_blocks;
uint32 block_remainder;
uint32 padded_length;

uint32 l;
uint32 t;
uint32 h[5];
uint32 a,b,c,d,e;
uint32 w[80];
uint32 temp;

    /* Calculate the number of 512 bit blocks */

    padded_length = message_length + 8; /* Add length for l */
    padded_length = padded_length + 1; /* Add the 0x01 bit postfix */

    l = message_length * 8;

    num_blocks = padded_length / 64;
    block_remainder = padded_length % 64;


    if (block_remainder > 0)
    {
        num_blocks++;
    }

    padded_length = padded_length + (64 - block_remainder);

     /* clear the padding field */
    for (i = message_length; i < (num_blocks * 64); i++)
    {
        message[i] = 0x00;
    }

    /* insert b1 padding bit */
    message[message_length] = 0x80;

    /* Insert l */
    message[(num_blocks*64)-1] = (uint8)( l        & 0xff);
    message[(num_blocks*64)-2] = (uint8)((l >> 8)  & 0xff);
    message[(num_blocks*64)-3] = (uint8)((l >> 16) & 0xff);
    message[(num_blocks*64)-4] = (uint8)((l >> 24) & 0xff);

    /* Set initial hash state */
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
    h[4] = 0xc3d2e1f0;

    for (i = 0; i < num_blocks; i++)
    {
        /* Prepare the message schedule */
        for (t=0; t < 80; t++)
        {
            if (t < 16)
            {
                w[t]  = (256*256*256) * message[(i*64)+(t*4)];
                w[t] += (256*256    ) * message[(i*64)+(t*4) + 1];
                w[t] += (256        ) * message[(i*64)+(t*4) + 2];
                w[t] +=                 message[(i*64)+(t*4) + 3];
            }
            else if (t < 80)
            {
                w[t] = rotl(1,(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]));
            }
        }

        /* Initialize the five working variables */
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];

        /* iterate a-e 80 times */

        for (t = 0; t < 80; t++)
        {
            temp = (rotl(5,a) + ft(t,b,c,d)) & 0xffffffff;
            temp = (temp + e) & 0xffffffff;
            temp = (temp + k(t)) & 0xffffffff;
            temp = (temp + w[t]) & 0xffffffff;
            e = d;
            d = c;
            c = rotl(30,b);
            b = a;
            a = temp;

        }

        /* compute the ith intermediate hash value */
        h[0] = (a + h[0]) & 0xffffffff;
        h[1] = (b + h[1]) & 0xffffffff;
        h[2] = (c + h[2]) & 0xffffffff;
        h[3] = (d + h[3]) & 0xffffffff;
        h[4] = (e + h[4]) & 0xffffffff;


    }

    digest[3]  = (uint8) ( h[0]       & 0xff);
    digest[2]  = (uint8) ((h[0] >> 8) & 0xff);
    digest[1]  = (uint8) ((h[0] >> 16) & 0xff);
    digest[0]  = (uint8) ((h[0] >> 24) & 0xff);

    digest[7]  = (uint8) ( h[1]       & 0xff);
    digest[6]  = (uint8) ((h[1] >> 8) & 0xff);
    digest[5]  = (uint8) ((h[1] >> 16) & 0xff);
    digest[4]  = (uint8) ((h[1] >> 24) & 0xff);

    digest[11]  = (uint8) ( h[2]       & 0xff);
    digest[10]  = (uint8) ((h[2] >> 8) & 0xff);
    digest[9] = (uint8) ((h[2] >> 16) & 0xff);
    digest[8] = (uint8) ((h[2] >> 24) & 0xff);

    digest[15] = (uint8) ( h[3]       & 0xff);
    digest[14] = (uint8) ((h[3] >> 8) & 0xff);
    digest[13] = (uint8) ((h[3] >> 16) & 0xff);
    digest[12] = (uint8) ((h[3] >> 24) & 0xff);

    digest[19] = (uint8) ( h[4]       & 0xff);
    digest[18] = (uint8) ((h[4] >> 8) & 0xff);
    digest[17] = (uint8) ((h[4] >> 16) & 0xff);
    digest[16] = (uint8) ((h[4] >> 24) & 0xff);

}

/******************************************************/
/* hmac-sha1()                                        */
/* Performs the hmac-sha1 keyed secure hash algorithm */
/******************************************************/
static uint8 step5data[MAX_MESSAGE_LENGTH+128];

void hmac_sha1(
                uint8 *key,
                uint32 key_length,
               const uint8 *data,
                uint32 data_length,
                uint8 *digest
                )

{
    uint32 b = 64; /* blocksize */
    uint8 ipad = 0x36;

    uint8 opad = 0x5c;

    uint8 k0[64];
    uint8 k0xorIpad[64];
    uint8 step7data[64];
   // uint8 step5data[MAX_MESSAGE_LENGTH+128];
    uint8 step8data[64+20];
    uint32 i;

    for (i=0; i<64; i++)
    {
        k0[i] = 0x00;
    }



    if (key_length != b)    /* Step 1 */
    {
        /* Step 2 */
        if (key_length > b)
        {
            sha1(key, key_length, digest);
            for (i=0;i<20;i++)
            {
                k0[i]=digest[i];
            }
        }
        else if (key_length < b)  /* Step 3 */
        {
            for (i=0; i<key_length; i++)
            {
                k0[i] = key[i];
            }
        }
    }
    else
    {
        for (i=0;i<b;i++)
        {
            k0[i] = key[i];
        }
    }

    /* Step 4 */
    for (i=0; i<64; i++)
    {
        k0xorIpad[i] = k0[i] ^ ipad;
    }
    /* Step 5 */
    for (i=0; i<64; i++)
    {
        step5data[i] = k0xorIpad[i];
    }
    for (i=0;i<data_length;i++)
    {
        step5data[i+64] = data[i];
    }

    /* Step 6 */
    sha1(step5data, data_length+b, digest);

    /* Step 7 */
    for (i=0; i<64; i++)
    {
        step7data[i] = k0[i] ^ opad;
    }

    /* Step 8 */
    for (i=0;i<64;i++)
    {
        step8data[i] = step7data[i];
    }
    for (i=0;i<20;i++)
    {
        step8data[i+64] = digest[i];
    }

    /* Step 9 */
    sha1(step8data, b+20, digest);

}
