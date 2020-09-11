#include "pcg_basic.h"



/**********************************************************************************************************************
 *  pcg_setseq_8_srandom_r()
 *********************************************************************************************************************/
/*! \brief         set the sequence of the 8 bit RNG algorithm.
 *  \details       
 *  \param[in]     initstate               Holds the initial state .
 *                 initseq                 Holds the initial sequence .
 *  \param[in,out] pcg_state_setseq_8* rng pointer to pcg_state_setseq_8 object.                  
 *                                         
 *  \param[out]    NONE      
 *  \return        NONE                   
 *
 *  \pre           NONE
 *                 
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/



/**********************************************************************************************************************
 * pcg8i_random_r()
 *********************************************************************************************************************/
/*! \brief         set the sequence of the 8 bit RNG algorithm.
 *  \details       
 *  \param[in]     NONE 
 *                 NONE            
 *  \param[in,out] pcg_state_setseq_8* rng pointer to pcg_state_setseq_8 object.                  
 *                                         
 *  \param[out]    NONE      
 *  \return        BYTE  return byte of the specified sequence each time of being called .                   
 *
 *  \pre           NONE
 *                 
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

extern inline uint32 pcg32_random_r(pcg32_random_t* rng);

extern inline void pcg32_srandom_r(pcg32_random_t* rng, uint64 initstate,
                     uint64 initseq);
