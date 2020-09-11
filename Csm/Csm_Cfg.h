/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Csm_Cfg.h
 *        \brief  MICROSAR Crypto Service Manager (CSM)
 *
 *      \details  Implementation of the MICROSAR Crypto Service Manager configuration (CSM)
 *
 *********************************************************************************************************************/
 
 
#ifndef CSM_CFG_H
#define CSM_CFG_H


/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/
#include "Platform_Types.h"
#include "Csm_Types.h"

/**********************************************************************************************************************
 *  LOCAL CONSTANT MACROS
 *********************************************************************************************************************/
 #define DIO_DEV_ERROR_DETECT (STD_ON)

 
#define hash_jobs 6
#define enc_jobs 4

#define CsmJobs_no 100
#define CsmKeys_no 100

#define service_keys_config_no 1

#define csmkey1 1
#define csmkey2 2
#define csmkey3 3
#define csmkey4 4
#define csmkey5 5
#define csmkey6 6

#define cryifkey1 1
#define cryifkey2 2
#define cryifkey3 3
#define cryifkey4 4
#define cryifkey5 5
#define cryifkey6 6
#define cryifkey7 7
#define cryifkey8 8
#define cryifkey9 9
#define cryifkey10 10

#define cryptokey1 1
#define cryptokey2 2
#define cryptokey3 3
#define cryptokey4 4
#define cryptokey5 5
#define cryptokey6 6
//key elements 
 

 
 
 
 
 
 
 


/* Container for configuration of a CSM hash. The container
name serves as a symbolic name for the identifier of a key
configuration. */
typedef struct {
/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmAlgorithmFamily;
/* Max size of the input data length in bytes */
uint8 CsmHashDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback. */
Crypto_ProcessingType CsmHashProcessing;
/* Size of the output hash length in bytes */
uint8 CsmHashResultLength;
}CsmHashConfig	;


/* Container for configuration of a CSM encryption interface. The container
name serves as a symbolic name for the identifier of an encryption
interface. */
typedef struct {
/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmEncryptAlgorithmFamily;
uint8 CsmEncryptAlgorithmFamilyCustom;

/* Size of the encryption key in bytes */
uint32 CsmEncryptAlgorithmKeyLength;

Crypto_AlgorithmModeType CsmEncryptAlgorithmMode ;
uint8 CsmEncryptAlgorithmModeCustom;

Crypto_AlgorithmFamilyType CsmEncryptAlgorithmSecondaryFamily;

uint8 CsmEncryptAlgorithmSecondaryFamilyCustom;
/* Max size of the input plaintext length in bytes */

uint32 CsmEncryptDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback */
Crypto_ProcessingType CsmEncryptProcessing;
/* Max size of the output cipher length in bytes */
uint32 CsmEncryptResultMaxLength;
	
}CsmEncryptConfig;

/* Container for configuration of a CSM decryption interface. The
container name serves as a symbolic name for the identifier of
an decryption interface. */
typedef struct {

/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmDecryptAlgorithmFamily;
uint8 CsmDecryptAlgorithmFamilyCustom;
/* Size of the encryption key in bytes */
uint32 CsmDecryptAlgorithmKeyLength;
Crypto_AlgorithmModeType CsmDecryptAlgorithmMode ;
uint8 CsmDecryptAlgorithmModeCustom;
Crypto_AlgorithmFamilyType CsmDecryptAlgorithmSecondaryFamily;
uint8 CsmDecryptAlgorithmSecondaryFamilyCustom;
/* Max size of the input ciphertext length in bytes */
uint32 CsmDecryptDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback */
Crypto_ProcessingType CsmDecryptProcessing;
/* Max size of the output plaintext length in bytes */
uint32 CsmDecryptResultMaxLength; 
	
}CsmDecryptConfig;
/* Container for configuration of a CSM mac generation interface.
The container name serves as a symbolic name for the
identifier of a MAC generation interface. */
typedef struct {
/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmMacGenerateAlgorithmFamily;
/* This is the name of the custom algorithm family,
if CRYPTO_ALGOFAM_CUSTOM is used as
CsmMacGenerateAlgorithmFamily */	
uint8 CsmMacGenerateAlgorithmFamilyCustom;
/* Size of the MAC key in bytes */
uint32 CsmMacGenerateAlgorithmKeyLength;
/* Determines the algorithm mode used for the crypto service */
Crypto_AlgorithmModeType CsmMacGenerateAlgorithmMode;
/* Name of the custom algorithm mode used for the crypto service */
uint8 CsmMacGenerateAlgorithmModeCustom;
/* Determines the secondary algorithm family used for the crypto service */
Crypto_AlgorithmFamilyType CsmMacGenerateAlgorithmSecondaryFamily;
/* This is the second name of the custom algorithm family, if
CRYPTO_ALGOFAM_CUSTOM is set as
CsmHashAlgorithmSecondaryFamilyCustom */
uint8 CsmMacGenerateAlgorithmSecondaryFamilyCustom;
/* Max size of the input data length in bytes */
uint32 CsmMacGenerateDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback. */
Crypto_ProcessingType CsmMacGenerateProcessing;
/* Size of the output MAC length in bytes */
uint32 CsmMacGenerateResultLength;

}CsmMacGenerateConfig	;

/* Container for configuration of a CSM MAC verification
interface. The container name serves as a symbolic name for
the identifier of a MAC generation interface */
typedef struct{
/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
Crypto_AlgorithmFamilyType CsmMacVerifyAlgorithmFamily;
/* Name of the custom algorithm family used for the crypto service */	
uint8 CsmMacVerifyAlgorithmFamilyCustom;
/* Size of the MAC key in bytes */
uint32 CsmMacVerifyAlgorithmKeyLength;
/* Determines the algorithm mode used for the crypto service */
Crypto_AlgorithmModeType CsmMacVerifyAlgorithmMode;
/* Name of the custom algorithm mode used for the crypto service */
uint8 CsmMacVerifyAlgorithmModeCustom;
/* Determines the secondary algorithm family used for the crypto service */
Crypto_AlgorithmFamilyType CsmMacVerifyAlgorithmSecondaryFamily;
/* This is the second the name of the custom algorithm, if
CRYPTO_ALGOFAM_CUSTOM is set as
CsmMacVerifyAlgorithmSecondaryFamily */
uint8 CsmMacVerifyAlgorithmSecondaryFamilyCustom;
/* Size of the input MAC length, that shall be verified, in BITS */
uint32 CsmMacVerifyCompareLength;
/* Max size of the input data length, for whichs MAC shall be verified, in bytes */
uint32 CsmMacVerifyDataMaxLength;
/* Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback.*/
Crypto_ProcessingType CsmMacVerifyProcessing;
	
}CsmMacVerifyConfig;
    

/* Container for configuration of a CSM random generator. The
container name serves as a symbolic name for the identifier of
a random generator configuration */
typedef struct {
	/* Determines the algorithm family used for the crypto service. This parameter defines
the most significant part of the algorithm. */
	Crypto_AlgorithmFamilyType CsmRandomGenerateAlgorithmFamily;
	/* Name of the custom algorithm family used for the crypto service. This is
the name of the custom algorithm family, if
CRYPTO_ALGOFAM_CUSTOM is used as CsmRandomAlgorithmFamily */
	uint8 CsmRandomGenerateAlgorithmFamilyCustom;
	/* Determines the algorithm mode used for the crypto service */
	Crypto_AlgorithmModeType CsmRandomGenerateAlgorithmMode;
	/* Name of the custom algorithm mode used for the crypto service. This is
the name of the custom algorithm family, if
CRYPTO_ALGOFAM_CUSTOM is used as
CsmRandomGenerateAlgorithmFamily. */
	uint8 CsmRandomGenerateAlgorithmModeCustom;
	/* Determines the algorithm family used for the crypto service */
	Crypto_AlgorithmFamilyType CsmRandomGenerateAlgorithmSecondaryFamily;
	/* Name of the custom secondary algorithm family used for the crypto
service. This is the second name of the custom algorithm family, if
CRYPTO_ALGOFAM_CUSTOM is set as Csm
RandomAlgorithmSecondaryFamily. */
	uint8 CsmRandomGenerateAlgorithmSecondaryFamilyCustom;
	/*Determines how the interface shall be used for that primitive. Synchronous
processing returns with the result while asynchronous processing returns without
processing the job. The caller will be notified by the corresponding callback */
	Crypto_ProcessingType CsmRandomGenerateProcessing;
	/* Size of the random generate key in bytes */
	uint32 CsmRandomGenerateResultLength;           
}CsmRandomGenerateConfig;






















typedef struct{
uint32 hashId;
uint32 EncId;
uint32 DecId;
uint32 RngId;
uint32 MacGId;
uint32 MacVId;
CsmHashConfig* HashPtr;
CsmEncryptConfig* EncPtr;
CsmDecryptConfig* DecPtr; 
CsmRandomGenerateConfig* RngPtr;
CsmMacGenerateConfig* MacGPtr;
CsmMacVerifyConfig* MacVPtr;
}AllJobs;
typedef struct {
    uint32 CryifKeyId;
}Keys_ID;

/* Container for configuration of CSM job. The container name
serves as a symbolic name for the identifier of a job
configuration. */
typedef struct {
/* Identifier of the CSM job. The set of actually configured identifiers shall be
consecutive and gapless. */
const uint32 CsmJobId ;
/* This parameter indicates, whether the callback function shall be called, if
the UPDATE operation has been finished. */
boolean CsmJobPrimitiveCallbackUpdateNotification;
/* Priority of the job.
The higher the value, the higher the job's priority. */
const uint32 CsmJobPriority;
/* Does the job need RTE interfaces?
True: the job needs RTE interfaces
False: the job needs no RTE interfaces */
boolean CsmJobUsePort;
/* This parameter refers to the key which shall be used for the CsmPrimitive.
It's possible to use a CsmKey for different jobs */
Keys_ID* CsmJobKeyRef; //pointer to array
/* This parameter refers to the used CsmCallback.
The referred CsmCallback is called when the crypto job has been finished */
uint16 CsmJobPrimitiveCallbackRef; 
/* This parameter refers to the used CsmPrimitive.
Different jobs may refer to one CsmPrimitive. The referred CsmPrimitive
provides detailed information on the actual cryptographic routine. */
AllJobs* CsmJobPrimitiveRef; //element id in array done ^^
/* This parameter refers to the queue.
The queue is used if the underlying crypto driver object is busy. The queue
refers also to the channel which is used. */
uint16 CsmJobQueueRef;
}CsmJob;

 //CsmJob CsmJobs[CsmJobs_no];
/* Container for configuration of a CSM key. The container name serves as a
symbolic name for the identifier of a key configuration. */
typedef struct {
/* Identifier of the CsmKey. The set of actually configured identifiers shall be
consecutive and gapless. */
uint16 CsmKeyId;
/* Does the key need RTE interfaces?
True: RTE interfaces used for this key
False: No RTE interfaces used for this key */
unsigned char CsmKeyUsePort;
/* This parameter refers to the used CryIfKey. The underlying CryIfKey refers
to a specific CryptoKey in the Crypto Driver. */
uint16 CsmKeyRef; 
}CsmKey;

/* Container for CSM key configurations. */
//CsmKey CsmKeys[CsmKeys_no];
/* Container for configuration of a CSM queue. The container
name serves as a symbolic name for the identifier of a queue
configuration.
A queue has two tasks:
1. queue jobs which cannot be processed since the underlying
hardware is busy and
2. refer to channel which shall be used */
typedef struct{
/* Size of the CsmQueue. If jobs cannot be processed by the underlying
hardware since the hardware is busy, the jobs stay in the prioritized queue.
If the queue is full, the next job will be rejected. */
uint16 CsmQueueSize;
/* Refers to the underlying Crypto Interface channel. */
uint16 CsmChannelRef;
}CsmQueue;


/* Key Management */
/*
typedef enum {
    service_MAC,
    service_Signature,
    service_Random,
    service_Cipher_AEAD,
    service_Key_Exchange,
    service_Key_Derivation,
    service_Key_Generate,
    service_Certificate_Parsing
}Crypto_Service;
typedef enum {
    Key_Material,
    Proof_SHE,
    Seed_State,
    Algorithm,
    Init_Vector,
    _2nd_Key_Material,
    Base,
    Private_Key,
    Own_Public_Key,
    Shared_Value,
    Password,
    Salt,
    Iterations,
    Seed,
    Certificate,
    Format,
    Current_Time,
    Version,
    Serial_Number,
    Signature_Algroithm,
    Issuer,
    Validity_start,
    Validity_end,
    Subject,
    Subject_Public_Key,
    Extensions,
    Signature
}key_element;


typedef struct{
    Crypto_Service Crypto_Service_cfg;
    key_element key_element_cfg;
    key_element_Name key_element_Name_cfg;
    key_element_ID key_element_ID_cfg;
}sevice_keys;
*/


#endif //CSM_CFG_H
