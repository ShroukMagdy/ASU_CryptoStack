


#ifndef PCG_BASIC_H
#include <inttypes.h>
#include "Platform_Types.h"


#define PCG_DEFAULT_MULTIPLIER_8   141U
#define PCG_Generated_Number_Length 4

typedef struct pcg_state_setseq_8  pcg8i_random_t;



struct pcg_state_setseq_8 {
    uint8 state;
    uint8 inc; /* Controls which RNG sequence (stream) is  selected. Must *always* be odd */
};

typedef struct pcg_state_setseq_64 pcg32_random_t;


struct pcg_state_setseq_64 {
    uint64 state;
    uint64 inc;    /* Controls which RNG sequence (stream) is  selected. Must *always* be odd */

};

inline uint32 pcg32_random_r(pcg32_random_t* rng)
{
    uint64 oldstate = rng->state;

    rng->state = oldstate * 6364136223846793005ULL + rng->inc;

    uint32 xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    uint32 rot = oldstate >> 59u;
    return  (xorshifted >> rot) | (xorshifted << ((-rot) & 31));



}
inline void pcg32_srandom_r(pcg32_random_t* rng, uint64 initstate, uint64 initseq)
{
    rng->state = 0U;
    rng->inc = (initseq << 1u) | 1u;
    pcg32_random_r(rng);
    rng->state += initstate;
    pcg32_random_r(rng);
}




#endif 
