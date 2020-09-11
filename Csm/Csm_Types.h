/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Csm_Types.h
 *        \brief  MICROSAR Crypto Service Manager (CSM)
 *
 *      \details  Implementation of the MICROSAR Crypto Service Manager types (CSM)
 *
 *********************************************************************************************************************/

#ifndef CSM_TYPES_H
#define CSM_TYPES_H

/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/
#include "Std_Types.h"

/**********************************************************************************************************************
 *  LOCAL CONSTANT MACROS
 *********************************************************************************************************************/
#define CRYPTO_E_BUSY ((Std_ReturnType)0x02U)               /* The service request failed because the service is still busy */
#define CRYPTO_E_SMALL_BUFFER ((Std_ReturnType)0x03U)       /* The service request failed because the provided buffer is too small to store the result */
#define CRYPTO_E_ENTROPY_EXHAUSTION ((Std_ReturnType)0x04U) /* The service request failed because the entropy of the random number generator is exhausted */
#define CRYPTO_E_QUEUE_FULL ((Std_ReturnType)0x05U)         /* The service request failed because the queue is full */
#define CRYPTO_E_KEY_READ_FAIL ((Std_ReturnType)0x06U)      /* The service request failed because read access was denied */
#define CRYPTO_E_KEY_WRITE_FAIL ((Std_ReturnType)0x07U)     /* The service request failed because the writing access failed */
#define CRYPTO_E_KEY_NOT_AVAILABLE ((Std_ReturnType)0x08U)  /* The service request failed because the key is not available */
#define CRYPTO_E_KEY_NOT_VALID ((Std_ReturnType)0x09U)      /* The service request failed because the key is invalid */
#define CRYPTO_E_KEY_SIZE_MISMATCH ((Std_ReturnType)0x0AU)  /* The service request failed because the key size does not match */
#define CRYPTO_E_COUNTER_OVERFLOW ((Std_ReturnType)0x0BU)   /* The service request failed because the counter is overflowed */
#define CRYPTO_E_JOB_CANCELED ((Std_ReturnType)0x0CU)       /* The service request failed because the Job has been canceled */

typedef Std_ReturnType Csm_ResultType;

#define E_SMALL_BUFFER ((Csm_ResultType)0x02U)       /* The service request failed because the provided buffer is too small to store the result. */
#define E_ENTROPY_EXHAUSTION ((Csm_ResultType)0x03U) /* The service request failed because the entropy of random number generator is exhausted. */
#define E_KEY_READ_FAIL ((Csm_ResultType)0x04U)      /* The service request failed because read access was denied. */
#define E_KEY_NOT_AVAILABLE ((Csm_ResultType)0x05U)  /* The service request failed because the key is not available. */
#define E_KEY_NOT_VALID ((Csm_ResultType)0x06U)      /* The service request failed because key was not valid. */
#define E_JOB_CANCELED ((Csm_ResultType)0x07U)       /* The service request failed because the job was canceled */

/* Enumeration of the algorithm family */
typedef enum
    {

    CRYPTO_ALGOFAM_NOT_SET= 0x00,
    CRYPTO_ALGOFAM_SHA1 =0x01,
    CRYPTO_ALGOFAM_SHA2_224 =0x02,
    CRYPTO_ALGOFAM_SHA2_256 =0x03,
    CRYPTO_ALGOFAM_SHA2_384 =0x04,
    CRYPTO_ALGOFAM_SHA2_512 =0x05,
    CRYPTO_ALGOFAM_SHA2_512_224 =0x06,
    CRYPTO_ALGOFAM_SHA2_512_256 =0x07,
    CRYPTO_ALGOFAM_SHA3_224 =0x08,
    CRYPTO_ALGOFAM_SHA3_256 =0x09,
    CRYPTO_ALGOFAM_SHA3_384 =0x0a,
    CRYPTO_ALGOFAM_SHA3_512 =0x0b,
    CRYPTO_ALGOFAM_SHAKE128 =0x0c,
    CRYPTO_ALGOFAM_SHAKE256 =0x0d,
    CRYPTO_ALGOFAM_RIPEMD160 =0x0e,
    CRYPTO_ALGOFAM_BLAKE_1_256=0x0f,
    CRYPTO_ALGOFAM_BLAKE_1_512=0x10,
    CRYPTO_ALGOFAM_BLAKE_2s_256=0x11,
    CRYPTO_ALGOFAM_BLAKE_2s_512=0x12,
    CRYPTO_ALGOFAM_3DES=0x13,
    CRYPTO_ALGOFAM_AES=0x14,
    CRYPTO_ALGOFAM_CHACHA=0x15,
    CRYPTO_ALGOFAM_RSA=0x16,
    CRYPTO_ALGOFAM_ED25519=0x17,
    CRYPTO_ALGOFAM_BRAINPOOL=0x18,
    CRYPTO_ALGOFAM_ECCNIST=0x19,
    CRYPTO_ALGOFAM_SECURECOUNTER=0x1a,
    CRYPTO_ALGOFAM_RNG=0x1b,
    CRYPTO_ALGOFAM_SIPHASH=0x1c,
    CRYPTO_ALGOFAM_ECIES=0x1d,
    CRYPTO_ALGOFAM_CUSTOM=0xff
}Crypto_AlgorithmFamilyType;
/* Enumeration of the algorithm mode */
typedef enum Crypto_AlgorithmModeType
{
    CRYPTO_ALGOMODE_NOT_SET =0x00,
    CRYPTO_ALGOMODE_ECB =0x01,
    CRYPTO_ALGOMODE_CBC =0x02,
    CRYPTO_ALGOMODE_CFB =0x03,
    CRYPTO_ALGOMODE_OFB =0x04,
    CRYPTO_ALGOMODE_CTR =0x05,
    CRYPTO_ALGOMODE_GCM =0x06,
    CRYPTO_ALGOMODE_XTS =0x07,
    CRYPTO_ALGOMODE_RSAES_OAEP =0x08,
    CRYPTO_ALGOMODE_RSAES_PKCS1_v1_5 =0x09,
    CRYPTO_ALGOMODE_RSASSA_PSS =0x0a,
    CRYPTO_ALGOMODE_RSASSA_PKCS1_v1_5 =0x0b,
    CRYPTO_ALGOMODE_8ROUNDS =0x0c,
    CRYPTO_ALGOMODE_12ROUNDS =0x0d,
    CRYPTO_ALGOMODE_20ROUNDS =0x0e,
    CRYPTO_ALGOMODE_HMAC =0x0f,
    CRYPTO_ALGOMODE_CMAC =0x10,
    CRYPTO_ALGOMODE_GMAC =0x11,
    CRYPTO_ALGOMODE_CTRDRBG =0x12,
    CRYPTO_ALGOMODE_SIPHASH_2_4 =0x13,
    CRYPTO_ALGOMODE_SIPHASH_4_8 =0x14,
    CRYPTO_ALGOMODE_CUSTOM =0xff
}Crypto_AlgorithmModeType;

/* Enumeration of the current job state */
typedef enum
{
    CRYPTO_JOBSTATE_IDLE,   /*Job is in the state "idle". This state is reached after
                                                    Csm_Init() or when the "Finish" state is finished*/
    CRYPTO_JOBSTATE_ACTIVE, /*Job is in the state "active". There was already some input
                                                            or there are intermediate results. This state is reached,
                                                            when the "update" or "start" operation finishes*/
} Crypto_JobStateType;
/* Enumeration of the kind of the service */
typedef enum
{
    CRYPTO_HASH,                /* Hash Service */
    CRYPTO_MACGENERATE,         /* MacGenerate Service */
    CRYPTO_MACVERIFY,           /*  MacVerify Service */
    CRYPTO_ENCRYPT,             /*  Encrypt Service */
    CRYPTO_DECRYPT,             /*  Decrypt Service */
    CRYPTO_AEADENCRYPT,         /*  AEADEncrypt Service */
    CRYPTO_AEADDECRYPT,         /*  AEADDecrypt Service */
    CRYPTO_SIGNATUREGENERATE,   /*  SignatureGenerate Service */
    CRYPTO_SIGNATUREVERIFY,     /*  SignatureVerify Service */
    CRYPTO_SECCOUNTERINCREMENT, /*  SecureCounterIncrement Service */
    CRYPTO_SECCOUNTERREAD,      /*  SecureCounterRead Service */
    CRYPTO_RANDOMGENERATE,      /*  RandomGenerate Service */
} Crypto_ServiceInfoType;
/*Enumeration which operation shall be performed. This enumeration is constructed from a bit mask,
  where the first bit indicates "Start", the second "Update" and the third "Finish"*/
typedef enum
{
    CRYPTO_OPERATIONMODE_START =0x01,
    CRYPTO_OPERATIONMODE_UPDATE =0x02,
    CRYPTO_OPERATIONMODE_STREAMSTART =0x03,
    CRYPTO_OPERATIONMODE_FINISH =0x04,
    CRYPTO_OPERATIONMODE_SINGLECALL =0x07


}Crypto_OperationModeType;
/* Structure which determines the exact algorithm. Note, not every algorithm needs to specify all fields. AUTOSAR shall only allow valid combinations */
typedef struct
{
    Crypto_AlgorithmFamilyType family;          /* The family of the algorithm */
    Crypto_AlgorithmFamilyType secondaryFamily; /* The secondary family of the algorithm */
    uint32 keyLength;                           /* The key length in bits to be used with that algorithm */
    Crypto_AlgorithmModeType mode;              /* The operation mode to be used with that algorithm */
} Crypto_AlgorithmInfoType;
/* Enumeration of the processing type */
typedef enum
{
    CRYPTO_PROCESSING_ASYNC, /*  Asynchronous job processing */
    CRYPTO_PROCESSING_SYNC,  /*  Synchronous job processing */
} Crypto_ProcessingType;
/* Enumeration of the result type of verification operations */
typedef enum
{
    CRYPTO_E_VER_OK,     /* The result of the verification is "true", i.e. the two compared elements are identical. This return code shall be given as value "0" */
    CRYPTO_E_VER_NOT_OK /* The result of the verification is "false", i.e. the two compared elements are not identical. This return code shall be given as value "1". */
} Crypto_VerifyResultType;
/* Structure which contains input and output information depending on the job and the crypto primitive */
typedef struct
{
    const uint8 *inputPtr;              /* Pointer to the input data. */
    uint32 inputLength;                 /* Contains the input length in bytes. */
    const uint8 *secondaryInputPtr;     /* Pointer to the secondary input data (for MacVerify, SignatureVerify) */
    uint32 secondaryInputLength;        /* Contains the secondary input length in bytes. */
    const uint8 *tertiaryInputPtr;      /* Pointer to the tertiary input data (for MacVerify, SignatureVerify). */
    uint32 tertiaryInputLength;         /* Contains the tertiary input length in bytes. */
    uint8 *outputPtr;                   /* Pointer to the output data. */
    uint32 *outputLengthPtr;            /* Holds a pointer to a memory location containing the output length in bytes. */
    uint8 *secondaryOutputPtr;          /* Pointer to the secondary output data. */
    uint32 *secondaryOutputLengthPtr;   /* Holds a pointer to a memory location containing the secondary output length in bytes. */
    uint64 input64;                     /* versatile input parameter */
    Crypto_VerifyResultType *verifyPtr; /* Output pointer to a memory location holding a Crypto_VerifyResultType */
    uint64 *output64Ptr;                /* Output pointer to a memory location holding a uint64. */
    Crypto_OperationModeType mode;      /* Indicator of the mode(s)/operation(s) to be performed */
} Crypto_JobPrimitiveInputOutputType;
/* Structure which contains job information (job ID and job priority) */
typedef struct
{
    const uint32 jobId;       /* The family of the algorithm */
    const uint32 jobPriority; /* Specifies the importance of the job (the higher, the more important) */
} Crypto_JobInfoType;
/* Structure which contains basic information about the crypto primitive */
typedef struct
{
    const uint32 resultLength;                /* Contains the result length in bytes. */
    const Crypto_ServiceInfoType service;     /* Contains the enum of the used service, e.g. Encrypt */
    const Crypto_AlgorithmInfoType algorithm; /* Contains the information of the used  algorithm */
} Crypto_PrimitiveInfoType;
/* Structure which contains further information, which depends on the job and the crypto primitive */
typedef struct
{
    const uint32 callbackId;                       /* Identifier of the callback function, to be called, if the configured service finished */
    const Crypto_PrimitiveInfoType *primitiveInfo; /* Pointer to a structure containing further configuration of the crypto primitives */
    const uint32 secureCounterId;                  /* Identifier of a secure counter */
    const uint32 cryIfKeyId;                       /* Identifier of the CryIf key */
    const Crypto_ProcessingType processingType;    /* Determines the synchronous or asynchronous behavior */
    const boolean callbackUpdateNotification;      /* Indicates, whether the callback function shall be called, if the UPDATE operation has finished */
} Crypto_JobPrimitiveInfoType;
/* Structure which contains further information, which depends on the job and the crypto primitive */
typedef struct
{
    const uint32 jobId;                                         /* Identifier for the job structure */
    Crypto_JobStateType jobState;                               /* Determines the current job state */
    Crypto_JobPrimitiveInputOutputType jobPrimitiveInputOutput; /* Structure containing input and output information depending on the job and the crypto primitive. */
    const Crypto_JobPrimitiveInfoType *jobPrimitiveInfo;        /* Pointer to a structure containing further information, which depends on the job and the crypto primitive */
    const Crypto_JobInfoType *jobInfo;                          /* Pointer to a structure containing further information, which depends on the job and the crypto primitive */
    uint32 cryptoKeyId;                                         /* Identifier of the Crypto Driver key. The identifier shall be written by the Crypto Interface */
} Crypto_JobType;

typedef struct {
     uint32 CSM_KEY_ID;
     uint32 CRYIF_KEY_ID;
     uint32 CRYPTO_KEY_ID;
}keys_ID;

typedef uint8 Csm_KeyDataType_Crypto;
#endif /* CSM_TYPES_H */
