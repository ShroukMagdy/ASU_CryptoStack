/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Csm.h
 *        \brief  MICROSAR Crypto Service Manager (CSM)
 *
 *      \details  Implementation of the MICROSAR Crypto Service Manager (CSM)
 *
 *********************************************************************************************************************/
#ifndef CSM_H
#define CSM_H
/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/
#include "Csm_Types.h"
#include "Csm_Cfg.h"
/**********************************************************************************************************************
 *  LOCAL CONSTANT MACROS
 *********************************************************************************************************************/
/*! Id for the company in the AUTOSAR */
#define CSM_VENDOR_ID (1U)
/*! CSM Module Id */
#define CSM_MODULE_ID (110U)
/*! CSM Instance Id */
#define CSM_INSTANCE_ID (0U)
/**********************************************************************************************************************
 *  GLOBAL DATA
 *********************************************************************************************************************/

extern CsmJob CsmJobs[];
extern CsmMacGenerateConfig job_CsmMacGenerateConfig[];
extern CsmMacVerifyConfig job_CsmMacVerifyConfig [];
extern CsmKey CsmKey_config[];
extern Keys_ID Keys_ID_config[];
/*********************************************************************************************************
*                                       SERVICE ID OF APIS                                               *
*********************************************************************************************************/
/*! Service ID for CSM Init */
#define CSM_INIT_SID 0x00
/*! Service ID for CSM GetVersionInfo */
#define Csm_GetVersionInfo_SID 0x3b
/*! Service ID for Csm_Hash */
#define Csm_Hash_SID 0x5d
/*! Service ID for Csm_MacGenerate */
#define Csm_MacGenerate_SID 0x60
/*! Service ID for Csm_MacVerify */
#define Csm_MacVerify_SID 0x61
/*! Service ID for Csm_Encrypt */
#define Csm_Encrypt_SID 0x5e
/*! Service ID for Csm_Decrypt */
#define Csm_Decrypt_SID 0x5f
/*! Service ID for Csm_RandomGenerate */
#define Csm_RandomGenerate_SID 0x66
/*! Service ID for Csm_KeyElementSet */
#define Csm_KeyElementSet_SID 0x78
/*! Service ID for Csm_KeySetValid */
#define Csm_KeySetValid_SID 0x67
/*! Service ID for Csm_KeyElementGet */
#define Csm_KeyElementGet_SID 0x68
/*! Service ID for Csm_RandomSeed */
#define Csm_RandomSeed_SID 0x69



/*!  Module Version 4.3.1 */
#define CSM_MAJOR_VERSION (4U)
#define CSM_MINOR_VERSION (3U)
#define CSM_PATCH_VERSION (1U)
/*********************************************************************************************************
*                                       Development Error Types                                          *
*********************************************************************************************************/
/*! API request called with invalid parameter (Nullpointer) */
#define CSM_E_PARAM_POINTER 0x01
/*! Buffer is too small for operation */
#define CSM_E_SMALL_BUFFER 0x03
/*! keyID is out of range */
#define CSM_E_PARAM_HANDLE 0x04
/*! API request called before initialization of CSM module */
#define CSM_E_UNINIT 0x05
/*! Initialization of CSM module failed */
#define CSM_E_INIT_FAILED 0x07
/*! Requested service is not initialized */
#define CSM_E_SERVICE_NOT_STARTED 0x09
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_Init(void)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Initializes the Csm status.
 *  \Service ID[hex]           0x00
 *  \param[in]     None.
 *  \param[in,out] None.
 *  \param[in]     None.
 *  \return        None.
 *  \pre           None.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00646"
 *  \satisfied by "SWS_Csm_00659"
 *********************************************************************************************************************/

void Csm_Init(void);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/

/**********************************************************************************************************************
 *  Csm_GetVersionInfo(Std_VersionInfoType *versioninfo)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Returns the version information of this module.
 *  \Service ID[hex]           0x3b
 *  \param[in]     None.
 *  \param[in,out] None.
 *  \param[out]    versioninfo             Pointer to where to store the version information of this module.
 *  \return        None.
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00705"
 *  \satisfied by "SWS_Csm_00407"
 *********************************************************************************************************************/
 
void Csm_GetVersionInfo(Std_VersionInfoType *versioninfo);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
/**********************************************************************************************************************
 *  Csm_Hash(uint32 jobId,
                        Crypto_OperationModeType mode,
                        const uint8 *dataPtr,
                        uint32 dataLength,
                        uint8 *resultPtr,
                        uint32 *resultLengthPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Uses the given data to perform the hash calculation and stores the hash.
 *  \Service ID[hex]           0x5d
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     dataPtr                 Contains the pointer to the data for which the hash shall be computed.
 *  \param[in]     dataLength              Contains the number of bytes to be hashed.
 *  \param[in,out] resultLengthPtr         Holds a pointer to the memory location in which the output length
                                           in bytes is stored. On calling this function, this parameter shall
                                           contain the size of the buffer provided by resultPtr. When the
                                           request has finished, the actual length of the returned value shall
                                           be stored.
 *  \param[out]    resultPtr               Contains the pointer to the data where the hash value shall be stored.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_SMALL_BUFFER   the provided buffer is too small to store the result.
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00980"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
Std_ReturnType Csm_Hash(uint32 jobId,
                        Crypto_OperationModeType mode,
                        const uint8 *dataPtr,
                        uint32 dataLength,
                        uint8 *resultPtr,
                        uint32 *resultLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/

 /**********************************************************************************************************************
 *  Csm_MacGenerate(uint32 jobId,
                               Crypto_OperationModeType mode,
                               const uint8 *dataPtr,
                               uint32 dataLength,
                               uint8 *macPtr,
                               uint32 *macLengthPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Uses the given data to perform a MAC generation and stores the MAC in the memory location pointed to by the MAC pointer.
 *  \Service ID[hex]           0x60
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     dataPtr                 Contains the pointer to the data for which the MAC shall be computed.
 *  \param[in]     dataLength              Contains the number of bytes to be hashed.
 *  \param[in,out] macLengthPtr            Holds a pointer to the memory location in which the output length
                                           in bytes is stored. On calling this function, this parameter shall
                                           contain the size of the buffer provided by macPtr. When the
                                           request has finished, the actual length of the returned MAC shall
                                           be stored.
 *  \param[out]    macPtr                  Contains the pointer to the data where the MAC shall be stored.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_KEY_NOT_VALID  request failed, the key's state is "invalid" 
 *  \return        CRYPTO_E_SMALL_BUFFER   the provided buffer is too small to store the result.
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00982"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/ 
Std_ReturnType Csm_MacGenerate(uint32 jobId,
                               Crypto_OperationModeType mode,
                               const uint8 *dataPtr,
                               uint32 dataLength,
                               uint8 *macPtr,
                               uint32 *macLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/

 /**********************************************************************************************************************
 *  Csm_MacVerify(uint32 jobId,
                             Crypto_OperationModeType mode,
                             const uint8 *dataPtr,
                             uint32 dataLength,
                             const uint8 *macPtr,
                             const uint32 macLength,
                             Crypto_VerifyResultType *verifyPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Verifies the given MAC by comparing if the MAC is generated with the given data.
 *  \Service ID[hex]           0x61
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     dataPtr                 Contains the pointer to the data for which the MAC shall be  verified.
 *  \param[in]     dataLength              Contains the number of bytes to be hashed.
 *  \param[in]     macPtr                  Holds a pointer to the MAC to be verified.
 *  \param[in]     macLength               Contains the MAC length in BITS to be verified.
 *  \param[in,out] None
 *  \param[out]    verifyPtr               Holds a pointer to the memory location, which will hold the result of the MAC verification.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_KEY_NOT_VALID  request failed, the key's state is "invalid" 
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_04050"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/ 
Std_ReturnType Csm_MacVerify(uint32 jobId,
                             Crypto_OperationModeType mode,
                             const uint8 *dataPtr,
                             uint32 dataLength,
                             const uint8 *macPtr,
                             const uint32 macLength,
                             Crypto_VerifyResultType *verifyPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/

  /**********************************************************************************************************************
 *  Csm_Encrypt(uint32 jobId,
                           Crypto_OperationModeType mode,
                           const uint8 *dataPtr,
                           uint32 dataLength,
                           uint8 *resultPtr,
                           uint32 *resultLengthPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Encrypts the given data and store the ciphertext in the memory location pointed by the result pointer.
 *  \Service ID[hex]           0x5e
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     dataPtr                 Contains the pointer to the data to be decrypted.
 *  \param[in]     dataLength              Contains the number of bytes to decrypt
 *  \param[in,out] resultLengthPtr         Holds a pointer to the memory location in which the output length
                                           information is stored in bytes. On calling this function, this
                                           parameter shall contain the size of the buffer provided by
                                           resultPtr. When the request has finished, the actual length of the
                                           returned value shall be stored.
 *  \param[out]    resultPtr               Contains the pointer to the memory location where the decrypted data shall be stored.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_KEY_NOT_VALID  request failed, the key's state is "invalid" 
 *  \return        CRYPTO_E_SMALL_BUFFER   the provided buffer is too small to store the result.
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00984"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
Std_ReturnType Csm_Encrypt(uint32 jobId,
                           Crypto_OperationModeType mode,
                           const uint8 *dataPtr,
                           uint32 dataLength,
                           uint8 *resultPtr,
                           uint32 *resultLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/

 /**********************************************************************************************************************
 *  Csm_Decrypt(    uint32 jobId,
                    Crypto_OperationModeType mode,
                    const uint8* dataPtr,
                    uint32 dataLength,
                    uint8* resultPtr,
                    uint32* resultLengthPtr )
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Decrypts the given encrypted data and store the decrypted plaintext in the memory location pointed by the result pointer.
 *  \Service ID[hex]           0x5f
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     dataPtr                 Contains the pointer to the data to be decrypted.
 *  \param[in]     dataLength              Contains the number of bytes to decrypt
 *  \param[in,out] resultLengthPtr         Holds a pointer to the memory location in which the output length
                                           information is stored in bytes. On calling this function, this
                                           parameter shall contain the size of the buffer provided by
                                           resultPtr. When the request has finished, the actual length of the
                                           returned value shall be stored.
 *  \param[out]    resultPtr               Contains the pointer to the memory location where the decrypted data shall be stored.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_KEY_NOT_VALID  request failed, the key's state is "invalid" 
 *  \return        CRYPTO_E_SMALL_BUFFER   the provided buffer is too small to store the result.
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00989"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_Decrypt(uint32 jobId,
                           Crypto_OperationModeType mode,
                           const uint8 *dataPtr,
                           uint32 dataLength,
                           uint8 *resultPtr,
                           uint32 *resultLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
  /**********************************************************************************************************************
 *  Csm_AEADEncrypt(uint32 jobId,
                               Crypto_OperationModeType mode,
                               const uint8 *plaintextPtr,
                               uint32 plaintextLength,
                               const uint8 *associatedDataPtr,
                               uint32 associatedDataLength,
                               uint8 *ciphertextPtr,
                               uint32 *ciphertextLengthPtr,
                               uint8 *tagPtr,
                               uint32 *tagLengthPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Uses the given input data to perform a AEAD encryption and stores the ciphertext and the MAC in the memory locations pointed by the ciphertext pointer and Tag pointer.
 *  \Service ID[hex]           0x62
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     plaintextPtr            Contains the pointer to the data to be encrypted.
 *  \param[in]     plaintextLength         Contains the number of bytes to encrypt.
 *  \param[in]     associatedDataPtr       Contains the pointer to the associated data.
 *  \param[in]     associatedDataLength    Contains the number of bytes of the associated data.    
 *  \param[in,out] ciphertextLengthPtr     Holds a pointer to the memory location in which the output
                                           length in bytes of the ciphertext is stored. On calling this
                                           function, this parameter shall contain the size of the buffer
                                           in bytes provided by resultPtr. When the request has
                                           finished, the actual length of the returned value shall be stored.
 *  \param[in,out] tagLengthPtr            Holds a pointer to the memory location in which the output
                                           length in bytes of the Tag is stored. On calling this function,
                                           this parameter shall contain the size of the buffer in bytes
                                           provided by resultPtr. When the request has finished, the
                                           actual length of the returned value shall be stored.
 *  \param[out]    ciphertextPtr           Contains the pointer to the data where the encrypted data shall be stored.
 *  \param[out]    tagPtr                  Contains the pointer to the data where the Tag shall be stored.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_KEY_NOT_VALID  request failed, the key's state is "invalid" 
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_01023"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_AEADEncrypt(uint32 jobId,
                               Crypto_OperationModeType mode,
                               const uint8 *plaintextPtr,
                               uint32 plaintextLength,
                               const uint8 *associatedDataPtr,
                               uint32 associatedDataLength,
                               uint8 *ciphertextPtr,
                               uint32 *ciphertextLengthPtr,
                               uint8 *tagPtr,
                               uint32 *tagLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/

 /**********************************************************************************************************************
 *  Csm_AEADDecrypt(uint32 jobId,
                               Crypto_OperationModeType mode,
                               const uint8 *ciphertextPtr,
                               uint32 ciphertextLength,
                               const uint8 *associatedDataPtr,
                               uint32 associatedDataLength,
                               const uint8 *tagPtr,
                               uint32 tagLength,
                               uint8 *plaintextPtr,
                               uint32 *plaintextLengthPtr,
                               Crypto_VerifyResultType *verifyPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Uses the given data to perform an AEAD encryption and stores the ciphertext and the MAC in the memory locations pointed by the ciphertext pointer and Tag pointer.
 *  \Service ID[hex]           0x63
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     ciphertextPtr           Contains the pointer to the data to be decrypted.
 *  \param[in]     ciphertextLength        Contains the number of bytes to decrypt.
 *  \param[in]     associatedDataPtr       Contains the pointer to the associated data.
 *  \param[in]     associatedDataLength    Contains the number of bytes of the associated data.  
 *  \param[in]     tagPtr                  Contains the pointer to the Tag to be verified.
 *  \param[in]     tagLength               Contains the length in bytes of the Tag to be verified.
 *  \param[in,out] plaintextLengthPtr      Holds a pointer to the memory location in which the output
                                           length in bytes of the paintext is stored. On calling this
                                           function, this parameter shall contain the size of the buffer
                                           provided by plaintextPtr. When the request has finished, the
                                           actual length of the returned value shall be stored.
 *  \param[out]    plaintextPtr            Contains the pointer to the data where the decrypted data shall be stored.
 *  \param[out]    verifyPtr               Contains the pointer to the result of the verification.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_KEY_NOT_VALID  request failed, the key's state is "invalid" 
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_01026"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/ 
 Std_ReturnType Csm_AEADDecrypt(uint32 jobId,
                               Crypto_OperationModeType mode,
                               const uint8 *ciphertextPtr,
                               uint32 ciphertextLength,
                               const uint8 *associatedDataPtr,
                               uint32 associatedDataLength,
                               const uint8 *tagPtr,
                               uint32 tagLength,
                               uint8 *plaintextPtr,
                               uint32 *plaintextLengthPtr,
                               Crypto_VerifyResultType *verifyPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
  /**********************************************************************************************************************
 *  Csm_SignatureGenerate(uint32 jobId,
                                     Crypto_OperationModeType mode,
                                     const uint8 *dataPtr,
                                     uint32 dataLength,
                                     uint8 *resultPtr,
                                     uint32 *resultLengthPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Uses the given data to perform the signature calculation and stores the signature in the memory location pointed by the result pointer.
 *  \Service ID[hex]           0x76
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     dataPtr                 Contains the pointer to the data to be signed.
 *  \param[in]     dataLength              Contains the number of bytes to sign.
 *  \param[in,out] resultLengthPtr         Holds a pointer to the memory location in which the output length
                                           in bytes of the signature is stored. On calling this function, this
                                           parameter shall contain the size of the buffer provided by
                                           resultPtr. When the request has finished, the actual length of the
                                           returned value shall be stored.
 *  \param[out]    resultPtr               Contains the pointer to the data where the signature shall be stored.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_KEY_NOT_VALID  request failed, the key's state is "invalid" 
 *  \return        CRYPTO_E_SMALL_BUFFER   the provided buffer is too small to store the result
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00992"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_SignatureGenerate(uint32 jobId,
                                     Crypto_OperationModeType mode,
                                     const uint8 *dataPtr,
                                     uint32 dataLength,
                                     uint8 *resultPtr,
                                     uint32 *resultLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
  /**********************************************************************************************************************
 *  Csm_SignatureVerify(uint32 jobId,
                                   Crypto_OperationModeType mode,
                                   const uint8 *dataPtr,
                                   uint32 dataLength,
                                   const uint8 *signaturePtr,
                                   uint32 signatureLength,
                                   Crypto_VerifyResultType *verifyPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Verifies the given MAC by comparing if the signature is generated with the given data
 *  \Service ID[hex]           0x64
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
 *  \param[in]     dataPtr                 Contains the pointer to the data to be  verified.
 *  \param[in]     dataLength              Contains the number of bytes.
 *  \param[in]     signaturePtr            Holds a pointer to the signature to be verified.
 *  \param[in]     signatureLength         Contains the signature length in bytes.
 *  \param[in,out] None
 *  \param[out]    verifyPtr               Holds a pointer to the memory location, which will hold the result of the signature verification.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_KEY_NOT_VALID  request failed, the key's state is "invalid" 
 *  \return        CRYPTO_E_SMALL_BUFFER   the provided buffer is too small to store the result
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00996"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_SignatureVerify(uint32 jobId,
                                   Crypto_OperationModeType mode,
                                   const uint8 *dataPtr,
                                   uint32 dataLength,
                                   const uint8 *signaturePtr,
                                   uint32 signatureLength,
                                   Crypto_VerifyResultType *verifyPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_SecureCounterIncrement(uint32 jobId,
                               uint64 stepSize)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Increments the value of the secure counter by the value contained in stepSize
 *  \Service ID[hex]           0x65
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in]     stepSize                Holds the value by which the counter will be incremented.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \return        CRYPTO_E_COUNTER_OVERFLOW  the counter is overflowed
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00998"
 *********************************************************************************************************************/
 Std_ReturnType Csm_SecureCounterIncrement(uint32 jobId,
                                          uint64 stepSize);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_SecureCounterRead(uint32 jobId,
                          uint64 *counterValuePtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Retrieves the value of a secure counter.
 *  \Service ID[hex]           0x65
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in,out] None
 *  \param[out]    counterValuePtr         Holds a pointer to the memory location which shall hold the value
                                           of the secure counter
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00999"
 *********************************************************************************************************************/
 Std_ReturnType Csm_SecureCounterRead(uint32 jobId,
                                     uint64 *counterValuePtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_RandomGenerate(uint32 jobId,
                       uint8 *resultPtr,
                       uint32 *resultLengthPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Generate a random number and stores it in the memory location pointed by the result pointer
 *  \Service ID[hex]           0x66
 *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
 *  \param[in,out] resultLengthPtr         Holds a pointer to the memory location in which the result length
                                           in bytes is stored. On calling this function, this parameter shall
                                           contain the number of random bytes, which shall be stored to the
                                           buffer provided by resultPtr. When the request has finished, the
                                           actual length of the returned value shall be stored.
 *  \param[out]    resultPtr               Holds a pointer to the memory location which will hold the result
                                           of the random number generation.
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_QUEUE_FULL     request failed, the queue is full
                                           of random number generator is exhausted.
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_01543"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_RandomGenerate(uint32 jobId,
                                  uint8 *resultPtr,
                                  uint32 *resultLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_KeyElementSet(uint32 keyId,
                      uint32 keyElementId,
                      const uint8 *keyPtr,
                      uint32 keyLength)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Sets the given key element bytes to the key identified by keyId
 *  \Service ID[hex]           0x78
 *  \param[in]     keyId                  Holds the identifier of the key for which a new material shall be set.
 *  \param[in]     keyElementId           Holds the identifier of the key element to be written.
 *  \param[in]     keyPtr                 Holds the pointer to the key element bytes to be processed.
 *  \param[in]     keyLength              Contains the number of key element bytes.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed because write access was denied
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE          Request failed because the key is not available.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH   Request failed, key element size does not match size of provided data.
 *  \pre           Csm status must be in active mode.
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00957"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeyElementSet(uint32 keyId,
                                 uint32 keyElementId,
                                 const uint8 *keyPtr,
                                 uint32 keyLength);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_KeySetValid(uint32 keyId)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Sets the key state of the key identified by keyId to valid
 *  \Service ID[hex]           0x67
 *  \param[in]     keyId                  Holds the identifier of the key for which a new material shall be validated.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                    request successful
 *  \return        E_NOT_OK                request failed
 *  \return        CRYPTO_E_BUSY           request failed, service is still busy
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00958"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeySetValid(uint32 keyId);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_KeyElementGet(uint32 keyId,
                                 uint32 keyElementId,
                                 uint8 *keyPtr,
                                 uint32 *keyLengthPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Retrieves the key element bytes from a specific key element of the key identified by the keyId and stores the key element in the memory location pointed by the key pointer
 *  \Service ID[hex]           0x68
 *  \param[in]     keyId                  Holds the identifier of the key for which a new material shall be validated.
 *  \param[in]     keyElementId           Holds the identifier of the key element to be extracted.
 *  \param[in,out] keyLengthPtr           Holds a pointer to the memory location in which the output buffer
                                          length in bytes is stored. On calling this function, this parameter
                                          shall contain the buffer length in bytes of the keyPtr. When the
                                          request has finished, the actual size of the written input bytes
                                          shall be stored.
 *  \param[out]    keyPtr                 Holds the pointer to the memory location where the key shall be copied to.
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \return        CRYPTO_E_BUSY          request failed, service is still busy
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE    request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_SMALL_BUFFER  the provided buffer is too small to store the result
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00959"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeyElementGet(uint32 keyId,
                                 uint32 keyElementId,
                                 uint8 *keyPtr,
                                 uint32 *keyLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_KeyElementCopy(const uint32 keyId,
                       const uint32 keyElementId,
                       const uint32 targetKeyId,
                       const uint32 targetKeyElementId)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       This function shall copy a key elements from one key to a target key
 *  \Service ID[hex]           0x71
 *  \param[in]     keyId                  Holds the identifier of the key whose key element shall be the source element.
 *  \param[in]     keyElementId           Holds the identifier of the key element which shall be the source for the copy operation.
 *  \param[in]     targetKeyId            Holds the identifier of the key whose key element shall be the destination element.
 *  \param[in]     targetKeyElementId     Holds the identifier of the key element which shall be the destination for the copy operation.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \return        CRYPTO_E_BUSY          request failed, service is still busy
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE    request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_KEY_WRITE_FAIL   Request failed, not allowed to write key element.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH: Request failed, key element sizes are not compatible.
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00969"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeyElementCopy(const uint32 keyId,
                                  const uint32 keyElementId,
                                  const uint32 targetKeyId,
                                  const uint32 targetKeyElementId);
 /**********************************************************************************************************************
 *  Csm_KeyCopy(const uint32 keyId,
                const uint32 targetKeyId)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       This function shall copy all key elements from the source key to a target key
 *  \Service ID[hex]           0x73
 *  \param[in]     keyId                  Holds the identifier of the key whose key element shall be the source element.
 *  \param[in]     targetKeyId            Holds the identifier of the key whose key element shall be the destination element.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \return        CRYPTO_E_BUSY          request failed, service is still busy
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE    request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_KEY_WRITE_FAIL   Request failed, not allowed to write key element.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH: Request failed, key element sizes are not compatible.
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_01034"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeyCopy(const uint32 keyId,
                           const uint32 targetKeyId);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_RandomSeed(uint32 keyId,
                   const uint8 *seedPtr,
                   uint32 seedLength)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       This function shall dispatch the random seed function to the configured crypto driver object
 *  \Service ID[hex]           0x69
 *  \param[in]     keyId                  Holds the identifier of the key for which a new seed shall be generated.
 *  \param[in]     seedPtr                Holds a pointer to the memory location which contains the data to feed the seed.
 *  \param[in]     seedLength             Contains the length of the seed in bytes.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_01051"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_RandomSeed(uint32 keyId,
                              const uint8 *seedPtr,
                              uint32 seedLength);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_KeyGenerate(uint32 keyId)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Generates new key material and store it in the key identified by keyId
 *  \Service ID[hex]           0x6a
 *  \param[in]     keyId                  Holds the identifier of the key for which a new seed shall be generated.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00955"
 *  \satisfied by "SWS_Csm_01005"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeyGenerate(uint32 keyId);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_KeyDerive(uint32 keyId,
                  uint32 targetKeyId)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Derives a new key by using the key elements in the given key identified by the keyId. The given key contains the key elements for the password and salt. The derived key is stored in the key element with the id 1 of the key identified by targetCryptoKeyId
 *  \Service ID[hex]           0x6b
 *  \param[in]     keyId                 Holds the identifier of the key which is used for key derivation.
 *  \param[in]     targetKeyId           Holds the identifier of the key which is used to store the derived key.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \return        CRYPTO_E_BUSY          Request Failed, Crypto Driver Object is Busy
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00956"
 *  \satisfied by "SWS_Csm_00489" 
 *  \satisfied by "SWS_Csm_01018"
 *  \satisfied by "SWS_Csm_01019" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeyDerive(uint32 keyId,
                             uint32 targetKeyId);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_KeyExchangeCalcPubVal(uint32 keyId,
                              uint8 *publicValuePtr,
                              uint32 *publicValueLengthPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Calculates the public value of the current user for the key exchange and stores the public key in the memory location pointed by the public value pointer
 *  \Service ID[hex]           0x6c
 *  \param[in]     keyId                 Holds the identifier of the key which shall be used for the key exchange protocol.
 *  \param[in,out] publicValueLengthPtr  Holds a pointer to the memory location in which the public
                                         value length information is stored. On calling this function,
                                         this parameter shall contain the size of the buffer provided
                                         by publicValuePtr. When the request has finished, the actual
                                         length of the returned value shall be stored.
 *  \param[out]    publicValuePtr        Contains the pointer to the data where the public value shall be stored.
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \return        CRYPTO_E_KEY_NOT_VALID    request failed, the key's state is "invalid"
 *  \return        CRYPTO_E_SMALL_BUFFER    the provided buffer is too small to store the result.
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00966"
 *  \satisfied by "SWS_Csm_01020"
 *  \satisfied by "SWS_Csm_00489" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeyExchangeCalcPubVal(uint32 keyId,
                                         uint8 *publicValuePtr,
                                         uint32 *publicValueLengthPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_KeyExchangeCalcSecret(uint32 keyId,
                                     const uint8 *partnerPublicValuePtr,
                                     uint32 partnerPublicValueLength)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Calculates the shared secret key for the key exchange with the key material of the key identified by the keyId and the partner public key. The shared secret key is stored as a key element in the same key
 *  \Service ID[hex]           0x6d
 *  \param[in]     keyId                 Holds the identifier of the key which shall be used for the key exchange protocol.
 *  \param[in]     partnerPublicValuePtr Holds the pointer to the memory location which contains the partner's public value.
 *  \param[in]     partnerPublicValueLength Contains the length of the partner's public value in bytes.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \return        CRYPTO_E_BUSY          Request Failed, Crypto Driver Object is Busy
 *  \return        CRYPTO_E_SMALL_BUFFER  the provided buffer is too small to store the result
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00967"
 *  \satisfied by "SWS_Csm_00489" 
 *  \satisfied by "SWS_Csm_01006"
 *********************************************************************************************************************/
 Std_ReturnType Csm_KeyExchangeCalcSecret(uint32 keyId,
                                         const uint8 *partnerPublicValuePtr,
                                         uint32* partnerPublicValueLength);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
  /**********************************************************************************************************************
 *  Csm_CertificateParse(const uint32 keyId)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       This function shall dispatch the certificate parse function to the CRYIF
 *  \Service ID[hex]           0x6e
 *  \param[in]     keyId                 Holds the identifier of the key to be used for the certificate parsing.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_01036"
 *  \satisfied by "SWS_Csm_00489" 
 *  \satisfied by "SWS_Csm_01037"
 *********************************************************************************************************************/
 Std_ReturnType Csm_CertificateParse(const uint32 keyId);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_CertificateVerify(const uint32 keyId,
                          const uint32 verifyCryIfKeyId,
                          Crypto_VerifyResultType *verifyPtr)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Verifies the certificate stored in the key referenced by verifyKeyId with the certificate stored in the key referenced by keyId
 *  \Service ID[hex]           0x74
 *  \param[in]     keyId                  Holds the identifier of the key which shall be used to validate the certificate.
 *  \param[in]     verifyCryIfKeyId       Holds the identifier of the key containing the certificate to be verified.
 *  \param[in,out] None
 *  \param[out]    verifyPtr              Holds a pointer to the memory location which will contain the result of the certificate verification.
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_01038"
 *  \satisfied by "SWS_Csm_00489" 
 *  \satisfied by "SWS_Csm_01040"
 *********************************************************************************************************************/
 Std_ReturnType Csm_CertificateVerify(const uint32 keyId,
                                     const uint32 verifyCryIfKeyId,
                                     Crypto_VerifyResultType *verifyPtr);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_CancelJob(uint32 job,
                  Crypto_OperationModeType mode)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Removes the job in the Csm Queue and calls the job's callback with the result CRYPTO_E_JOB_CANCELED. It also passes the cancellation command to the CryIf to try to cancel the job in the Crypto Driver
 *  \Service ID[hex]           0x6f
 *  \param[in]     job                    Holds the identifier of the job to be canceled
 *  \param[in]     mode                   Not used, just for interface compatibility provided.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00968"
 *  \satisfied by "SWS_Csm_00489" 
 *  \satisfied by "SWS_Csm_01021"
 *  \satisfied by "SWS_Csm_01030" 
 *********************************************************************************************************************/
 Std_ReturnType Csm_CancelJob(uint32 job,
                             Crypto_OperationModeType mode);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_CallbackNotification(Crypto_JobType *job,
                             Csm_ResultType result)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       Notifies the CSM that a job has finished. This function is used by the underlying layer (CRYIF)
 *  \Service ID[hex]           0x70
 *  \param[in]     job                    Holds a pointer to the job, which has finished.
 *  \param[in]     result                 Contains the result of the cryptographic operation.
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        E_OK                   request successful
 *  \return        E_NOT_OK               request failed
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00970"
 *  \satisfied by "SWS_Csm_01053" 
 *  \satisfied by "SWS_Csm_01044"
 *********************************************************************************************************************/
 void Csm_CallbackNotification(Crypto_JobType *job,
                              Csm_ResultType result);
/**********************************************************************************************************************
 *  LOCAL FUNCTION PROTOTYPES
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  Csm_MainFunction(void)
 *********************************************************************************************************************/
/*! \brief         
 *  \details       API to be called cyclically to process the requested jobs. The Csm_MainFunction shall check the queues for jobs to pass to the underlying CRYIF
 *  \Service ID[hex]           0x01
 *  \param[in]     None
 *  \param[in,out] None
 *  \param[out]    None
 *  \return        None
 *  \pre           
 *  \context       TASK
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *  \satisfied by "SWS_Csm_00479"
 *********************************************************************************************************************/
 void Csm_MainFunction(void);

 /**********************************************************************************************************************
  *  Csm_ProcessJob()
  *********************************************************************************************************************/
 /*! \brief         This interface handels the priority and synchronization of jobs.
  *  \details       This function unifies all external calls to call Csm_ProcessJob.
  *  \param[in]     job_Processing          Holds the type of processing synchronous or asynchronous.
  *  \param[in]     job_Priority            Holds the priority of the job.
  *  \param[in]     jobId                   Holds the identifier of the job using the CSM service.
  *  \param[in]     mode                    Indicates which operation mode(s) to perfom.
  *  \param[in,out] None
  *  \param[out]    resultPtr               Contains the pointer to the data where the hash value shall be stored.
  *  \param[in]     macLength               Contains the MAC length in BITS to be verified.
  *  \param[out]    None
  *  \return        E_OK                   request successful
  *  \return        E_NOT_OK               request failed
  *  \pre
  *  \context       TASK
  *  \reentrant     TRUE
  *  \synchronous   TRUE
  *********************************************************************************************************************/
 Std_ReturnType Csm_ProcessJob(Crypto_ProcessingType job_Processing,
                               uint32 job_Priority,
                               uint32 jobId,
                               Crypto_OperationModeType mode);
#endif  /* CSM_H */


