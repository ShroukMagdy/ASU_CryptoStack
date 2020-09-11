#include "adaptor.h"


/**********************************************************************************************************************
 * AlgoSHA1_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha1 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *  \param[in,out] NONE
 *
 *  \param[out]    hash                    Pointer to hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

void AlgoSHA1_adaptor(const uint8 data[],uint32 len,uint8 * hash )

{

	SHA1_CTX ctx ={{0},0,0,{0},{0}};
	sha1_init(&ctx);
	sha1_update(&ctx, data, len);
	sha1_final(&ctx, hash);
	

	
}
/**********************************************************************************************************************
 * AlgoSHA244_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha224 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *  \param[in,out] NONE
 *
 *  \param[out]    hash                    Pointer to hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void AlgoSHA224_adaptor( const uint8 data[],uint32 len,uint8* hash)
{
    SHA224_CTX ctx={{0},0,0,{0}};
  
	sha224_init(&ctx);
	sha224_update(&ctx, data, len);
	sha224_final(&ctx, hash);
 
}
/**********************************************************************************************************************
 * AlgoSHA256_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha256 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *
 *  \param[out]    hash                    Pointer to hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void AlgoSHA256_adaptor( const uint8 data[],uint32 len,uint8* hash)
{
    SHA256_CTX ctx ={{0},0,0,{0}};

	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, hash);
   
}

/**********************************************************************************************************************
 * AlgoSHA384_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha384 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *
 *  \param[out]    hash                    Pointer  hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void AlgoSHA384_adaptor( const uint8 data[],uint32 len,uint8 * hash)
{
    sha384_ctx ctx ={0,0,{0},{0}};

       sha384_init(&ctx);
       sha384_update(&ctx, data, len);
       sha384_final(&ctx, hash);


	

}
/**********************************************************************************************************************
 * AlgoSHA512_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and sha512 functions.
 *  \details       This function creates buffer to store hash_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *
 *  \param[out]    hash                    Pointer to hash o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void AlgoSHA512_adaptor( const uint8 data[],uint32 len,uint8 * hash)

{
   
sha512_ctx ctx ={0,0,{0},{0}};

   sha512_init(&ctx);
   sha512_update(&ctx, data, len);
   sha512_final(&ctx, hash);

  
}
/**********************************************************************************************************************
 * AlgoMD5_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and MD5 functions.
 *  \details       This function creates buffer to store md5_final function output then its o/p pointer hash points to
 *                 the buffer.
 *
 *  \param[in]     data                    Pointer to i/p data
 *  \param[in]     len                     Param len holds the length of i/p data.
 *
 *  \param[out]    hash                    Pointer to MD5 o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

void AlgoMD5_adaptor( const uint8 data[],uint32 len,uint8* hash)
{
    MD5_CTX ctx ={{0},0,0,{0}};
   
	md5_init(&ctx);
	md5_update(&ctx, data, len);
	md5_final(&ctx, hash);
	
}


/**********************************************************************************************************************
 * Algo3DESEn_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and 3des encryption function.
 *
 *  \param[in]     data                    Pointer to i/p data to be encrypted.
 *  \param[in]     len                     Param len holds the length of i/p data.
 *  \Param[in]     key                     Pointer to 3des key.
 *  \Param[in]     StartByte               Param StartByte holds the index at which the key material array starts.
 *  \Param[in]     ivstart                 Param ivstart  holds the index at which the key IV array starts.
 *  \param[out]    outptr                   Pointer to encryption o/p.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void Algo3DESEn_adaptor( const uint8 data[],uint32 len,uint8* outptr,uint8 key[],uint32 StartByte ,uint32 ivstart){
uint64 DES_in=0; 
uint8 a =0; uint64 b; 
uint32 counter =0; uint32 ipcount=0;
uint32 i=0; uint64 result=0; uint8 arr[8]={0};
uint64 keys [3]={0}; uint32 rundes =0;
uint8 * initial_vector=&key[ivstart];
ipcount=StartByte;

for (i = 0; i <3 ; i++)
{
    for (a=0 ;a<8;a++)
    {
        keys[i]|=((uint64)key[ipcount]<<(8*(7-a)));
        ipcount=ipcount+1;
    }

}

if (rundes==0){

 for (i=0 ;i <8 ;i++)
 {
     arr[i]=data[i] ^ initial_vector[i];
 }

}
a=0;
i=0;
ipcount=0;

for (i = 0; i <(len/8) ; i++) { //32 8 bit 4 byte
for (a=0 ;a<8;a++)
{
    if(rundes==0){
	DES_in|=((uint64)arr[ipcount]<<(8*(7-a)));
   }

else {

    DES_in|=((uint64)(data[ipcount]^outptr[ipcount-8])<<(8*(7-a)));

}

	ipcount=ipcount+1;
}

result=encrypt_DES(DES_in,keys, b);

for (a=0 ;a<8;a++)
{
   outptr[counter]=(result)>>(8*(7-a));
 	counter =counter +1;
}

DES_in=0;
result=0;
rundes=rundes+1;
}

rundes=0;
	counter =0; ipcount=0;
	}
/**********************************************************************************************************************
 * Algo3DESDe_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and 3des decryption function.
 *
 *  \param[in]     data                    Pointer to i/p data to be decrypted.
 *  \param[in]     len                     Param len holds the length of i/p data.
 *  \Param[in]     key                     Pointer to key elements array.
 *  \Param[in]     StartByte               Param StartByte holds the index at which the key material array starts.
 *  \Param[in]     ivstart                 Param ivstart  holds the index at which the key IV array starts.
 *  \param[out]    outptr                  Pointer to decryption output.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void Algo3DESDe_adaptor( const uint8 data[],uint32 len,uint8* outptr,uint8 key[],uint32 StartByte ,uint32 ivstart){
uint64 DES_in=0; uint32 rundes =0;
uint8 a =0; uint64 b;
uint32 counter =0; uint32 ipcount=0;
uint32 i=0; uint64 result=0;
uint8 * initial_vector=&key[ivstart];
uint64 keys [3]={0};

ipcount=StartByte;
for (i = 0; i <3 ; i++)
{
    for (a=0 ;a<8;a++)
    {
        keys[i]|=((uint64)key[ipcount]<<(8*(7-a)));
        ipcount=ipcount+1;
    }

}

a=0;
i=0;
ipcount=0;



for (i = 0; i <(len/8) ; i++) { //32 8 bit 4 byte
    for (a=0 ;a<8;a++)
    {



        DES_in|=((uint64)(data[ipcount])<<(8*(7-a)));



        ipcount=ipcount+1;
    }
result=decrypt_DES(DES_in,keys, b);
for (a=0 ;a<8;a++)
{
   outptr[counter]=(result)>>(8*(7-a));
   if (rundes==0){
        outptr[counter]=outptr[counter] ^ initial_vector[a];
        }

    else
    {

        outptr[counter]=outptr[counter] ^ (data[(rundes-1)*8+a]);
    }
    counter =counter +1;
}




DES_in=0;
result=0;
rundes=rundes+1;
}
counter =rundes;
rundes=0;
    counter =0; ipcount=0;
    }

/**********************************************************************************************************************
 * Algo32RNG_adaptor()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and PCG RNG functions.
 *  \details
 *  \param[in]     seed                    Pointer to key elements array.
 *  \param[in]     seedIndex               Param seedIndex  holds the index at which the seed array starts.
 *  \param[out]    result                  Pointer to RNG array.
 *  \param[out]    resLength               Pointer holds the length of RNG array.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void Algo32RNG_adaptor(uint8* result, uint32*resLength,uint8* seed ,uint32 seedIndex ){

	uint8 ll=0,a=0,Si=0,seedCounter=0 ; uint32 f=0 ,i=0 ,counter =0,result_algo =0;
  uint64 seedArray [2]={0,0};
	pcg32_random_t rng ={0,0};

	
   ll =seedIndex;
	for(Si=0;Si<2;Si++){
	for(seedCounter=0;seedCounter<8;seedCounter++)
	{
        seedArray[Si]|=((uint64)seed[ll]<<(8*(7-seedCounter)));
         
		    ll=ll+1;
	}

}


	ll=0;
  
	pcg32_srandom_r( (pcg32_random_t*)&rng,seedArray[0],seedArray[1]);
	f=(*resLength)/4; // result in bytes
	for (i = 0; i <f ; i++) {
		result_algo= pcg32_random_r(&rng);
		for (a=0 ;a<4;a++)
    {
    result[counter]=(result_algo)>>(8*(3-a));
		counter =counter+1;
    }
	
}
	counter=0; 
	}

/**********************************************************************************************************************
 * Algo_AesEn()
 *********************************************************************************************************************/
/*! \brief         adaptor between crypto_processJob() and AES encryption function.
 *
 *  \param[in]     data                    Pointer to i/p data to be encrypted.
 *  \param[in]     len                     Param len holds the length of i/p data.
 *  \Param[in]     key                     Pointer to key elements array.
 *  \Param[in]     keyLen                  Pointer to the length of key material array.
 *  \Param[in]     StartByte               Param StartByte holds the index at which the key material array starts.
 *  \Param[in]     ivstart                 Param ivstart  holds the index at which the key IV array starts.
 *  \param[out]    outptr                  Pointer to encryption output.
 *  \pre           NONE
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
	void Algo_AesEn(const uint8 data[],uint32 len,uint8* outptr,uint8 key [],uint32 StartByte ,uint32 keyLen ,uint32 ivstart ) {
	    uint32 i=0;
	    uint32 rundes =0;
	    uint8 arr [16]={0};
	    uint8 buf [16]={0};
	    uint8 arrcount=0;
	    uint8 * keyptr = &key[StartByte];
        uint8* initial_vector=&key[ivstart];
        uint32 a=0;
        if (rundes==0){

         for (i=0 ;i <16 ;i++)
         {
             arr[i]=data[i] ^ initial_vector[i];
         }

        }

        i=0;
        for (i = 0; i <(len/16) ; i++) {
            if(rundes==0){
	        encrypt_AES(arr,len,outptr,keyptr,keyLen);
            }

            else
            {
                for (a=rundes*16 ;a<(16+rundes*16) ;a++)
                {
                  arr[arrcount]=data[a]^outptr[a-16];
                    arrcount=arrcount+1;
                }
                encrypt_AES(arr,len,buf,keyptr,keyLen);
                arrcount=0;

                for (a=rundes*16 ;a<(16+rundes*16) ;a++)
                {
                  outptr[a]=buf[arrcount];
                    arrcount=arrcount+1;
                }
            }
            rundes=rundes+1;
            arrcount=0;
        }
  rundes=0;
	}

/**********************************************************************************************************************
	 * Algo_AesDe()
 *********************************************************************************************************************/
	/*! \brief         adaptor between crypto_processJob() and AES decryption function.
	 *
	 *  \param[in]     data                    Pointer to i/p data to be decrypted.
	 *  \param[in]     len                     Param len holds the length of i/p data.
	 *  \Param[in]     key                     Pointer to key elements array.
	 *  \Param[in]     keyLen                  Pointer to the length of key material array.
	 *  \Param[in]     StartByte               Param StartByte holds the index at which the key material array starts.
	 *  \Param[in]     ivstart                 Param ivstart  holds the index at which the key IV array starts.
	 *  \param[out]    outptr                  Pointer to decryption output.
	 *  \pre           NONE
	 *  \context       TASK
	 *  \reentrant     TRUE
	 *  \synchronous   TRUE
	 *********************************************************************************************************************/

	void Algo_AesDe(const uint8 data[],uint32 len,uint8* outptr,uint8 key [],uint32 StartByte ,uint32 keyLen ,uint32 ivstart ) {
	            uint32 i=0;
	            uint32 rundes =0;
	            uint8 arr [16]={0};
	            uint8 buf [16]={0};
	            uint8 buf_out [16]={0};
	            uint8 arrcount=0;
	            uint8 * keyptr = &key[StartByte];
	            uint8* initial_vector=&key[ivstart];
	            uint32 a=0;
	            uint32 b=0;

	          for (i = 0; i <(len/16) ; i++) {

	                for (a=rundes*16 ;a<(16+rundes*16) ;a++)
	                {
	                   arr[arrcount]=data[a];
	                    arrcount=arrcount+1;
	                }
	                arrcount=0;
	                decrypt_AES(arr,len,buf,keyptr,keyLen);


	                for (a=0; a<16;a++){

	                      if (rundes==0){




	                          buf_out[b]= buf[a] ^ initial_vector[a];


	                      }
	                      else
	                      {
	                              outptr[b]=buf[arrcount]^data[(rundes-1)*16+a];
	                              arrcount=arrcount+1;

	                                          }

	                      b=b+1;


	                                      }
	                rundes=rundes+1;

	                arrcount=0;
	            }
	      rundes=0;
	      arrcount=0;

	         for (i = 0; i<16 ; i++) {
	             outptr[i]=buf_out[i];
	         }

	        }

/**********************************************************************************************************************
	 * Algo_HMAC_SHA1_adaptor()
*********************************************************************************************************************/
	/*! \brief         adaptor between crypto_processJob() and Hmac functions.
	 *
	 *  \param[in]     data                    Pointer to i/p data to be hashed.
	 *  \param[in]     len                     Param len holds the length of i/p data.
	 *  \Param[in]     key                     Pointer to key elements array.
	 *  \Param[in]     StartByte               Param StartByte holds the index at which the key array starts.
	 *  \Param[in]     keyLen                  Pointer to the length of key array.
	 *  \param[out]    outptr                  Pointer to hmac output.
	 *  \pre           NONE
	 *  \context       TASK
	 *  \reentrant     TRUE
	 *  \synchronous   TRUE
	 *********************************************************************************************************************/

	void Algo_HMAC_SHA1_adaptor(const uint8 data[],uint32 len,uint8* outptr,uint8 key [],uint32 StartByte ,uint32 keyLen )

	{
	    uint8 * keyptr = &key[StartByte];

	    hmac_sha1(
	                    keyptr,
	                    keyLen,
	                    data,
	                    len,
	                    outptr
	                    );
	}
/**********************************************************************************************************************
	     * Algo_CMAC_AES_adaptor ()
*********************************************************************************************************************/
	    /*! \brief         adaptor between crypto_processJob() and Cmac functions.
	     *
	     *  \param[in]     data                    Pointer to i/p data to be hashed.
	     *  \param[in]     len                     Param len holds the length of i/p data.
	     *  \Param[in]     key                     Pointer to key elements array.
	     *  \Param[in]     StartByte               Param StartByte holds the index at which the key array starts.
	     *  \Param[in]     keyLen                  Pointer to the length of key array.
	     *  \param[out]    outptr                  Pointer to hmac output.
	     *  \pre           NONE
	     *  \context       TASK
	     *  \reentrant     TRUE
	     *  \synchronous   TRUE
	     *********************************************************************************************************************/
void Algo_CMAC_AES_adaptor(const uint8 data[],uint32 len,uint8* outptr,uint8 key [],uint32 StartByte ,uint32 keyLen )
{
    uint8 * keyptr = &key[StartByte];
    uint8** nonConstData= (uint8**)((uint8*)&data); //const to non const
    AES_CMAC(keyptr, *nonConstData,len,outptr);

}
	
