#ifndef Crypto_H_
#define Crypto_H_

#include "Csm_types.h"
#include "Crypto_Cfg.h"
#include "adaptor.h"

#define CRYPTO_MODULE_ID  114 
#define Objects 1

//Crypto_JobType job_queue[100];


//Services IDs

#define Crypto_Init_ID 0x00
#define Crypto_GetVersionInfo_ID 0x01
#define Crypto_ProcessJob_ID 0x03
#define Crypto_CancelJob_ID 0x0e
#define Crypto_KeyElementSet_ID 0x04
#define Crypto_KeySetValid_ID 0x05
#define Crypto_KeyElementGet_ID 0x06
//development errors
#define CRYPTO_E_UNINIT 0x00
#define CRYPTO_E_INIT_FAILED 0x01
#define CRYPTO_E_PARAM_POINTER 0x02
#define CRYPTO_E_PARAM_HANDLE 0x04
#define CRYPTO_E_PARAM_VALUE 0x05
//runtime errors
#define CRYPTO_E_RE_SMALL_BUFFER (Std_ReturnType)0x00
#define CRYPTO_E_RE_KEY_NOT_AVAILABLE 0x01
#define CRYPTO_E_RE_KEY_READ_FAIL 0x02
#define CRYPTO_E_RE_ENTROPY_EXHAUSTED 0x03

//General API

void Crypto_Init(void);
void Crypto_GetVersionInfo(Std_VersionInfoType* versioninfo) ;
//Job Processing Interface
Std_ReturnType Crypto_ProcessJob( uint32 objectId, Crypto_JobType* job );
//Job Cancellation Interface
Std_ReturnType Crypto_CancelJob( uint32 objectId, Crypto_JobInfoType* job);
//Key Setting Interface
Std_ReturnType Crypto_KeyElementSet( uint32 cryptoKeyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength );
Std_ReturnType Crypto_KeySetValid( uint32 cryptoKeyId );
//Key Extraction Interface
Std_ReturnType Crypto_KeyElementGet( uint32 cryptoKeyId, uint32 keyElementId, uint8* resultPtr, uint32* resultLengthPtr );
Std_ReturnType Crypto_KeyCopy( uint32 cryptoKeyId, uint32 targetCryptoKeyId );
Std_ReturnType Crypto_KeyElementIdsGet( uint32 cryptoKeyId, uint32* keyElementIdsPtr, uint32* keyElementIdsLengthPtr );
//Key Generation Interface
Std_ReturnType Crypto_RandomSeed( uint32 cryptoKeyId , const uint8* seedPtr, uint32 seedLength );
Std_ReturnType Crypto_KeyGenerate( uint32 cryptoKeyId );
//Key Derivation Interface
Std_ReturnType Crypto_KeyDerive( uint32 cryptoKeyId, uint32 targetCryptoKeyId );
//Key Exchange Interface
Std_ReturnType Crypto_KeyExchangeCalcPubVal( uint32 cryptoKeyId, uint8* publicValuePtr, uint32* publicValueLengthPtr );
Std_ReturnType Crypto_KeyExchangeCalcSecret( uint32 cryptoKeyId, const uint8* partnerPublicValuePtr, uint32* partnerPublicValueLength );
//Certificate Interface
Std_ReturnType Crypto_CertificateParse( uint32 cryptoKeyId );
Std_ReturnType Crypto_CertificateVerify( uint32 cryptoKeyId, uint32 verifyCryptoKeyId, Crypto_VerifyResultType* verifyPtr );
//Main function
void Crypto_MainFunction( void );
/*
extern CryptoKeys kys [];
extern CryptoKeyElement elements [];
extern uint8 dataElements [];
extern CryptoKeyConfigInfo info [];
*/


extern uint8 ElementsData[];
extern KeyElementType KeyElementsDataRef[];
extern CryptoKeyElement KeyElementsCfg[];
extern KeyType KeyElementRef[];

#endif
