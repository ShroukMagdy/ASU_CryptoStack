



#include "SHA384-512.h"

#define SHFR(x, n)    (x >> n)
#define ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define CH(x, y, z)  ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))


#define SHA512_F1(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define SHA512_F2(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SHA512_F3(x) (ROTR(x,  1) ^ ROTR(x,  8) ^ SHFR(x,  7))
#define SHA512_F4(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ SHFR(x,  6))

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8) ((x)      );       \
    *((str) + 2) = (uint8) ((x) >>  8);       \
    *((str) + 1) = (uint8) ((x) >> 16);       \
    *((str) + 0) = (uint8) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32) *((str) + 3)      )    \
           | ((uint32) *((str) + 2) <<  8)    \
           | ((uint32) *((str) + 1) << 16)    \
           | ((uint32) *((str) + 0) << 24);   \
}

#define UNPACK64(x, str)                      \
{                                             \
    *((str) + 7) = (uint8) ((x)      );       \
    *((str) + 6) = (uint8) ((x) >>  8);       \
    *((str) + 5) = (uint8) ((x) >> 16);       \
    *((str) + 4) = (uint8) ((x) >> 24);       \
    *((str) + 3) = (uint8) ((x) >> 32);       \
    *((str) + 2) = (uint8) ((x) >> 40);       \
    *((str) + 1) = (uint8) ((x) >> 48);       \
    *((str) + 0) = (uint8) ((x) >> 56);       \
}

#define PACK64(str, x)                        \
{                                             \
    *(x) =   ((uint64) *((str) + 7)      )    \
           | ((uint64) *((str) + 6) <<  8)    \
           | ((uint64) *((str) + 5) << 16)    \
           | ((uint64) *((str) + 4) << 24)    \
           | ((uint64) *((str) + 3) << 32)    \
           | ((uint64) *((str) + 2) << 40)    \
           | ((uint64) *((str) + 1) << 48)    \
           | ((uint64) *((str) + 0) << 56);   \
}

/* Macros used for loops unrolling */



#define SHA512_SCR(i)                         \
{                                             \
    w[i] =  SHA512_F4(w[i -  2]) + w[i -  7]  \
          + SHA512_F3(w[i - 15]) + w[i - 16]; \
}



#define SHA512_EXP(a, b, c, d, e, f, g ,h, j)               \
{                                                           \
    t1 = wv[h] + SHA512_F2(wv[e]) + CH(wv[e], wv[f], wv[g]) \
         + sha512_k[j] + w[j];                              \
    t2 = SHA512_F1(wv[a]) + MAJ(wv[a], wv[b], wv[c]);       \
    wv[d] += t1;                                            \
    wv[h] = t1 + t2;                                        \
}



uint64 sha384_h0[8] =
            {0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL,
             0x9159015a3070dd17ULL, 0x152fecd8f70e5939ULL,
             0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
             0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};

uint64 sha512_h0[8] =
            {0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
             0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
             0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
             0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};



uint64 sha512_k[80] =
            {0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
             0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
             0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
             0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
             0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
             0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
             0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
             0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
             0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
             0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
             0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
             0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
             0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
             0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
             0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
             0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
             0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
             0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
             0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
             0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
             0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
             0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
             0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
             0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
             0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
             0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
             0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
             0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
             0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
             0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
             0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
             0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
             0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
             0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
             0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
             0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
             0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
             0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
             0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
             0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

/* SHA-256 functions */





/* SHA-512 functions */

void sha512_transf(sha512_ctx *ctx, const uint8 *message,
                   uint32 block_nb)
{
    uint64 w[80];
    uint64 wv[8];
    uint64 t1, t2;
    const uint8 *sub_block;
    uint32 i, j;

    for (i = 0; i < (int) block_nb; i++) {
        sub_block = message + (i << 7);

#ifndef UNROLL_LOOPS
        for (j = 0; j < 16; j++) {
            PACK64(&sub_block[j << 3], &w[j]);
        }

        for (j = 16; j < 80; j++) {
            SHA512_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 80; j++) {
            t1 = wv[7] + SHA512_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + sha512_k[j] + w[j];
            t2 = SHA512_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
#else
        PACK64(&sub_block[  0], &w[ 0]); PACK64(&sub_block[  8], &w[ 1]);
        PACK64(&sub_block[ 16], &w[ 2]); PACK64(&sub_block[ 24], &w[ 3]);
        PACK64(&sub_block[ 32], &w[ 4]); PACK64(&sub_block[ 40], &w[ 5]);
        PACK64(&sub_block[ 48], &w[ 6]); PACK64(&sub_block[ 56], &w[ 7]);
        PACK64(&sub_block[ 64], &w[ 8]); PACK64(&sub_block[ 72], &w[ 9]);
        PACK64(&sub_block[ 80], &w[10]); PACK64(&sub_block[ 88], &w[11]);
        PACK64(&sub_block[ 96], &w[12]); PACK64(&sub_block[104], &w[13]);
        PACK64(&sub_block[112], &w[14]); PACK64(&sub_block[120], &w[15]);

        SHA512_SCR(16); SHA512_SCR(17); SHA512_SCR(18); SHA512_SCR(19);
        SHA512_SCR(20); SHA512_SCR(21); SHA512_SCR(22); SHA512_SCR(23);
        SHA512_SCR(24); SHA512_SCR(25); SHA512_SCR(26); SHA512_SCR(27);
        SHA512_SCR(28); SHA512_SCR(29); SHA512_SCR(30); SHA512_SCR(31);
        SHA512_SCR(32); SHA512_SCR(33); SHA512_SCR(34); SHA512_SCR(35);
        SHA512_SCR(36); SHA512_SCR(37); SHA512_SCR(38); SHA512_SCR(39);
        SHA512_SCR(40); SHA512_SCR(41); SHA512_SCR(42); SHA512_SCR(43);
        SHA512_SCR(44); SHA512_SCR(45); SHA512_SCR(46); SHA512_SCR(47);
        SHA512_SCR(48); SHA512_SCR(49); SHA512_SCR(50); SHA512_SCR(51);
        SHA512_SCR(52); SHA512_SCR(53); SHA512_SCR(54); SHA512_SCR(55);
        SHA512_SCR(56); SHA512_SCR(57); SHA512_SCR(58); SHA512_SCR(59);
        SHA512_SCR(60); SHA512_SCR(61); SHA512_SCR(62); SHA512_SCR(63);
        SHA512_SCR(64); SHA512_SCR(65); SHA512_SCR(66); SHA512_SCR(67);
        SHA512_SCR(68); SHA512_SCR(69); SHA512_SCR(70); SHA512_SCR(71);
        SHA512_SCR(72); SHA512_SCR(73); SHA512_SCR(74); SHA512_SCR(75);
        SHA512_SCR(76); SHA512_SCR(77); SHA512_SCR(78); SHA512_SCR(79);

        wv[0] = ctx->h[0]; wv[1] = ctx->h[1];
        wv[2] = ctx->h[2]; wv[3] = ctx->h[3];
        wv[4] = ctx->h[4]; wv[5] = ctx->h[5];
        wv[6] = ctx->h[6]; wv[7] = ctx->h[7];

        j = 0;

        do {
            SHA512_EXP(0,1,2,3,4,5,6,7,j); j++;
            SHA512_EXP(7,0,1,2,3,4,5,6,j); j++;
            SHA512_EXP(6,7,0,1,2,3,4,5,j); j++;
            SHA512_EXP(5,6,7,0,1,2,3,4,j); j++;
            SHA512_EXP(4,5,6,7,0,1,2,3,j); j++;
            SHA512_EXP(3,4,5,6,7,0,1,2,j); j++;
            SHA512_EXP(2,3,4,5,6,7,0,1,j); j++;
            SHA512_EXP(1,2,3,4,5,6,7,0,j); j++;
        } while (j < 80);

        ctx->h[0] += wv[0]; ctx->h[1] += wv[1];
        ctx->h[2] += wv[2]; ctx->h[3] += wv[3];
        ctx->h[4] += wv[4]; ctx->h[5] += wv[5];
        ctx->h[6] += wv[6]; ctx->h[7] += wv[7];
#endif /* !UNROLL_LOOPS */
    }
}

void sha512(const uint8 *message, uint32 len,
            uint8 *digest)
{
    sha512_ctx ctx;

    sha512_init(&ctx);
    sha512_update(&ctx, message, len);
    sha512_final(&ctx, digest);
}

void sha512_init(sha512_ctx *ctx)
{
#ifndef UNROLL_LOOPS
	uint8 i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha512_h0[i];
    }
#else
    ctx->h[0] = sha512_h0[0]; ctx->h[1] = sha512_h0[1];
    ctx->h[2] = sha512_h0[2]; ctx->h[3] = sha512_h0[3];
    ctx->h[4] = sha512_h0[4]; ctx->h[5] = sha512_h0[5];
    ctx->h[6] = sha512_h0[6]; ctx->h[7] = sha512_h0[7];
#endif /* !UNROLL_LOOPS */

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha512_update(sha512_ctx *ctx, const uint8 *message,
                   uint32 len)
{
    uint32 block_nb;
    uint32 new_len, rem_len, tmp_len;
    const uint8 *shifted_message;
    uint32 i=0;
    tmp_len = SHA512_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    for (i=0;i<rem_len;i++)
    {
    	ctx->block[ctx->len+i]=message[i];
    }

    if (ctx->len + len < SHA512_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA512_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha512_transf(ctx, ctx->block, 1);
    sha512_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA512_BLOCK_SIZE;


    for(i=0;i<rem_len;i++)
    {
    	ctx->block[i]=shifted_message[(block_nb << 7)+i];
    }

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 7;
}

void sha512_final(sha512_ctx *ctx, uint8 *digest)
{
    uint32 block_nb;
    uint32 pm_len;
    uint32 len_b;
    uint32 j=0;
#ifndef UNROLL_LOOPS
    uint8 i;
#endif

    block_nb = 1 + ((SHA512_BLOCK_SIZE - 17)
                     < (ctx->len % SHA512_BLOCK_SIZE));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 7;

    for (j=0;j< pm_len - ctx->len;j++)
    {
    	ctx->block[ctx->len+j]=0;
    }
    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha512_transf(ctx, ctx->block, block_nb);

#ifndef UNROLL_LOOPS
    for (i = 0 ; i < 8; i++) {
        UNPACK64(ctx->h[i], &digest[i << 3]);
    }
#else
    UNPACK64(ctx->h[0], &digest[ 0]);
    UNPACK64(ctx->h[1], &digest[ 8]);
    UNPACK64(ctx->h[2], &digest[16]);
    UNPACK64(ctx->h[3], &digest[24]);
    UNPACK64(ctx->h[4], &digest[32]);
    UNPACK64(ctx->h[5], &digest[40]);
    UNPACK64(ctx->h[6], &digest[48]);
    UNPACK64(ctx->h[7], &digest[56]);
#endif /* !UNROLL_LOOPS */
}

/* SHA-384 functions */

void sha384(const uint8 *message, uint32 len,
            uint8 *digest)
{
    sha384_ctx ctx;

    sha384_init(&ctx);
    sha384_update(&ctx, message, len);
    sha384_final(&ctx, digest);
}

void sha384_init(sha384_ctx *ctx)
{
#ifndef UNROLL_LOOPS
    uint8 i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha384_h0[i];
    }
#else
    ctx->h[0] = sha384_h0[0]; ctx->h[1] = sha384_h0[1];
    ctx->h[2] = sha384_h0[2]; ctx->h[3] = sha384_h0[3];
    ctx->h[4] = sha384_h0[4]; ctx->h[5] = sha384_h0[5];
    ctx->h[6] = sha384_h0[6]; ctx->h[7] = sha384_h0[7];
#endif /* !UNROLL_LOOPS */

    ctx->len = 0;
    ctx->tot_len = 0;
}

void sha384_update(sha384_ctx *ctx, const uint8 *message,
                   uint32 len)
{
    uint32 block_nb;
    uint32 new_len, rem_len, tmp_len;
    const uint8 *shifted_message;
    uint32 k=0;
    tmp_len = SHA384_BLOCK_SIZE - ctx->len;
    rem_len = len < tmp_len ? len : tmp_len;

    for(k=0;k<rem_len;k++)
    {
    	ctx->block[ctx->len+k]=message[k];
    }

    if (ctx->len + len < SHA384_BLOCK_SIZE) {
        ctx->len += len;
        return;
    }

    new_len = len - rem_len;
    block_nb = new_len / SHA384_BLOCK_SIZE;

    shifted_message = message + rem_len;

    sha512_transf(ctx, ctx->block, 1);
    sha512_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA384_BLOCK_SIZE;


    for(k=0;k<rem_len;k++)
        {
        	ctx->block[k]=shifted_message[(block_nb << 7)+k];
        }

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 7;
}

void sha384_final(sha384_ctx *ctx, uint8 *digest)
{
    uint32 block_nb;
    uint32 pm_len;
    uint32 len_b;
    uint32 x;
#ifndef UNROLL_LOOPS
    uint8 i;
#endif

    block_nb = (1 + ((SHA384_BLOCK_SIZE - 17)
                     < (ctx->len % SHA384_BLOCK_SIZE)));

    len_b = (ctx->tot_len + ctx->len) << 3;
    pm_len = block_nb << 7;

    for (x=0;x< pm_len - ctx->len;x++)
        {
        	ctx->block[ctx->len+x]=0;
        }

    ctx->block[ctx->len] = 0x80;
    UNPACK32(len_b, ctx->block + pm_len - 4);

    sha512_transf(ctx, ctx->block, block_nb);

#ifndef UNROLL_LOOPS
    for (i = 0 ; i < 6; i++) {
        UNPACK64(ctx->h[i], &digest[i << 3]);
    }
#else
    UNPACK64(ctx->h[0], &digest[ 0]);
    UNPACK64(ctx->h[1], &digest[ 8]);
    UNPACK64(ctx->h[2], &digest[16]);
    UNPACK64(ctx->h[3], &digest[24]);
    UNPACK64(ctx->h[4], &digest[32]);
    UNPACK64(ctx->h[5], &digest[40]);
#endif /* !UNROLL_LOOPS */
}



