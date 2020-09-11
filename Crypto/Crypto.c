/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Crypto.c
 *        \brief  MICROSAR Crypto Driver (Crypto)
 *
 *      \details  Implementation of the MICROSAR Crypto Driver (Crypto)
 *
 *********************************************************************************************************************/
/**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/

#include "Crypto.h"
#include "CryIf.h"
#include "Det.h"

/*General API*/

static boolean Cryptoinit = FALSE;
static boolean GetKeyIDx(KeyType key[], uint32 ID, uint32 *KeyIDx);
static void SetElementData(uint8 ElementsData[], const uint8 *Data,
                           uint32 StartingIDx, uint32 KeyLenght);
static boolean GetKeyElementIDx(KeyElementType keyElement[], uint32 ID,
                                uint32 *KeyIDx, uint32 KeyElementStartingIDx,
                                uint32 KeyElementEndingIDx);
static void GetElementData(uint8 ElementsData[], uint8 *Data,
                           uint32 StartingIDx, uint32 KeyLenght);
static boolean sameMac(const uint8 *secondinputMac, uint8 *verifyMac,
                       const uint32 verifyMac_length);

boolean GetKeyIDx(KeyType key[], uint32 ID, uint32 *KeyIDx)
{
    uint32 i = 0;
    boolean flag = FALSE;
    for (i = 0; i <= KeysNumber; i++)
    {
        if (key[i].CryptoKeyId == ID)
        {
            *KeyIDx = i;
            flag = TRUE;
            break;
        }
        else
        {

        }
    }
    return flag;

}

boolean GetKeyElementIDx(KeyElementType keyElement[], uint32 ID, uint32 *KeyIDx,
                         uint32 KeyElementStartingIDx,
                         uint32 KeyElementEndingIDx)
{
    uint32 i = 0;
    boolean flag = FALSE;

    for (i = KeyElementStartingIDx; i <= KeyElementEndingIDx; i++)
    {
        if (keyElement[i].CryptoKeyElementId == ID)
        {
            *KeyIDx = i;
            flag = TRUE;
            break;
        }
        else
        {

        }
    }
    return flag;

}

void SetElementData(uint8 ElementsData[], const uint8 *Data, uint32 StartingIDx,
                    uint32 KeyLength)
{
    uint32 i = 0;

    for (i = 0; i < KeyLength; i++)
    {
        ElementsData[StartingIDx + i] = *(Data + i);
    }
}

void GetElementData(uint8 ElementsData[], uint8 *Data, uint32 StartingIDx,
                    uint32 KeyLength)
{
    uint32 i = 0;
    for (i = 0; i < KeyLength; i++)
    {
        *(Data + i) = ElementsData[StartingIDx + i];
    }
}

boolean sameMac(const uint8 *secondinputMac, uint8 *verifyMac,
                const uint32 verifyMac_length)
{
    uint32 i = 0;
    boolean match = TRUE;
    for (i = 0; i < verifyMac_length; i++)
    {

        if (secondinputMac[i] != verifyMac[i])
        {
            match = FALSE;
            break;
        }
    }

    return match;
}

/**********************************************************************************************************************
 *  Crypto_Init()
 *********************************************************************************************************************/
/*! \brief         Initializes the Crypto Driver.
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

void Crypto_Init(void)
{

    Cryptoinit = TRUE;

    if (FALSE == Cryptoinit)
    {
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_Init_ID,
                        CRYPTO_E_INIT_FAILED);
    }
    /*SWS_Crypto_00045 satisfied */
}

/**********************************************************************************************************************
 *  Crypto_GetVersionInfo()
 *********************************************************************************************************************/
/*! \brief         Returns the version information of this module.
 *  \param[in]     versioninfo             Pointer to where to store the version information of this module.
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
void Crypto_GetVersionInfo(Std_VersionInfoType *versioninfo)
{
    if (NULL == versioninfo)
    {
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_GetVersionInfo_ID,
                        CRYPTO_E_PARAM_POINTER);
    }
    /*SWS_Crypto_00047 satisfied*/
}

/**********************************************************************************************************************
 *  Crypto_ProcessJob()
 *********************************************************************************************************************/
/*! \brief         Performs the crypto primitive, that is configured in the job parameter.
 *  \param[in]     objectId                Holds the identifier of the Crypto Driver Object.
 *  \param[in,out] job                     Pointer to the configuration of the job. Contains structures with user and
 *                                         primitive relevant information.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_VALID  Request failed, the key is not valid.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, a key element has the wrong size.
 *  \return        CRYPTO_E_ENTROPY_EXHAUSTION Request failed, the entropy is exhausted.
 *  \return        CRYPTO_E_COUNTER_OVERFLOW The counter is overflowed.
 *  \return        CRYPTO_E_QUEUE_FULL     Request failed, the queue is full.
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \return        CRYPTO_E_JOB_CANCELED   The service request failed because the synchronous Job has been canceled.
 *  \reentrant     TRUE
 *  \synchronous   Depends on the job configuration
 *********************************************************************************************************************/
Std_ReturnType Crypto_ProcessJob(uint32 objectId, Crypto_JobType *job)
{
    Std_ReturnType ret = E_NOT_OK;
    uint32 KeyIDx = 0;
    uint32 KeyElementIDx = 0;
    uint32 KeyElementIVIDx = 0;
    boolean checkMac = FALSE;
    uint8 verifyArr[16] = { 0 };
    if (FALSE == Cryptoinit)
    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_ProcessJob_ID,
                        CRYPTO_E_UNINIT);
#endif
        ret = E_NOT_OK;
    }
    /*SWS_Crypto_00057 satisfied*/

    else if (NULL == job)
    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_ProcessJob_ID,
                        CRYPTO_E_PARAM_POINTER);
#endif
        ret = E_NOT_OK;
    }
    /*SWS_Crypto_00059 satisfied*/

    else
    {
        /*Hash*/

        if (CRYPTO_HASH == (job->jobPrimitiveInfo->primitiveInfo->service))
        {

            if (NULL == (job->jobPrimitiveInputOutput.inputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif

                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00059 satisfied*/

            else if (0 == (job->jobPrimitiveInputOutput.inputLength))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00142 satisfied*/

            else if (NULL == (job->jobPrimitiveInputOutput.outputLengthPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif
                ret = E_NOT_OK;
            }

            /*SWS_Crypto_00059 satisfied*/

            else if (0 == *(job->jobPrimitiveInputOutput.outputLengthPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00142 satisfied*/
            else if (NULL == (job->jobPrimitiveInputOutput.outputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif
                ret = E_NOT_OK;

            }
            /*SWS_Crypto_00070 satisfied*/
            else
            {
                /*SHA1*/
                if (CRYPTO_ALGOFAM_SHA1
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {

                    if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                            < SHA1_BLOCK_SIZE)
                    {
                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_RE_SMALL_BUFFER);
                        ret = CRYPTO_E_SMALL_BUFFER;
                    }
                    /*SWS_Crypto_00136 satisfied*/
                    else
                    {

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_START)
                        {
                            job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_UPDATE)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {

                            }
                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_FINISH)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {
                                AlgoSHA1_adaptor(
                                        job->jobPrimitiveInputOutput.inputPtr,
                                        job->jobPrimitiveInputOutput.inputLength,
                                        job->jobPrimitiveInputOutput.outputPtr);

                                *(job->jobPrimitiveInputOutput.outputLengthPtr) =
                                SHA1_BLOCK_SIZE;
                                ret = E_OK;

                            }

                        }
                    }

                }
                /*SHA224*/
                else if (CRYPTO_ALGOFAM_SHA2_224
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {
                    if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                            < SHA224_BLOCK_SIZE)
                    {
                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_RE_SMALL_BUFFER);
                        ret = CRYPTO_E_SMALL_BUFFER;
                    }
                    /*SWS_Crypto_00136 satisfied*/
                    else
                    {
                        /*call the algorithm*/
                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_START)
                        {
                            job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_UPDATE)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {

                            }
                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_FINISH)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {
                                AlgoSHA224_adaptor(
                                        job->jobPrimitiveInputOutput.inputPtr,
                                        job->jobPrimitiveInputOutput.inputLength,
                                        job->jobPrimitiveInputOutput.outputPtr);

                                *(job->jobPrimitiveInputOutput.outputLengthPtr) =
                                SHA224_BLOCK_SIZE;

                                ret = E_OK;
                            }
                        }
                    }
                }
                /*SHA256*/
                else if (CRYPTO_ALGOFAM_SHA2_256
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {
                    if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                            < SHA256_BLOCK_SIZE)
                    {
                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_RE_SMALL_BUFFER);
                        ret = CRYPTO_E_SMALL_BUFFER;
                    }
                    /*SWS_Crypto_00136 satisfied*/
                    else
                    {
                        /*call the algorithm*/
                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_START)
                        {
                            job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_UPDATE)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {

                            }
                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_FINISH)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {
                                AlgoSHA256_adaptor(
                                        job->jobPrimitiveInputOutput.inputPtr,
                                        job->jobPrimitiveInputOutput.inputLength,
                                        job->jobPrimitiveInputOutput.outputPtr);
                                *(job->jobPrimitiveInputOutput.outputLengthPtr) =
                                SHA256_BLOCK_SIZE;
                            }
                        }
                        ret = E_OK;
                    }
                }
                /*SHA384*/
                else if (CRYPTO_ALGOFAM_SHA2_384
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {

                    if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                            < SHA384_DIGEST_SIZE)
                    {
                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_RE_SMALL_BUFFER);
                        ret = CRYPTO_E_SMALL_BUFFER;
                    }

                    /*SWS_Crypto_00136 satisfied*/
                    else
                    {
                        /*call the algorithm*/
                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_START)
                        {
                            job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_UPDATE)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {

                            }
                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_FINISH)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {
                                AlgoSHA384_adaptor(
                                        job->jobPrimitiveInputOutput.inputPtr,
                                        job->jobPrimitiveInputOutput.inputLength,
                                        job->jobPrimitiveInputOutput.outputPtr);
                                *(job->jobPrimitiveInputOutput.outputLengthPtr) =
                                SHA384_BLOCK_SIZE;

                                ret = E_OK;
                            }
                        }
                    }

                }
                /*SHA512*/
                else if (CRYPTO_ALGOFAM_SHA2_512
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {
                    if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                            < SHA512_DIGEST_SIZE)
                    {
                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_RE_SMALL_BUFFER);
                        ret = CRYPTO_E_SMALL_BUFFER;
                    }
                    /*SWS_Crypto_00136 satisfied*/
                    else
                    {
                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_START)
                        {
                            job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_UPDATE)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {

                            }
                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_FINISH)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {
                                /*call the algorithm*/
                                AlgoSHA512_adaptor(
                                        job->jobPrimitiveInputOutput.inputPtr,
                                        job->jobPrimitiveInputOutput.inputLength,
                                        job->jobPrimitiveInputOutput.outputPtr);
                                *(job->jobPrimitiveInputOutput.outputLengthPtr) =
                                SHA512_BLOCK_SIZE;

                                ret = E_OK;
                            }
                        }
                    }
                }
                /*MD5*/
                else if (CRYPTO_ALGOFAM_CUSTOM
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {
                    if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                            < MD5_BLOCK_SIZE)
                    {
                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_RE_SMALL_BUFFER);
                        ret = CRYPTO_E_SMALL_BUFFER;
                    }
                    /*SWS_Crypto_00136 satisfied*/
                    else
                    {

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_START)
                        {
                            job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_UPDATE)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {

                            }
                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_FINISH)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {
                                /*call the algorithm*/
                                AlgoMD5_adaptor(
                                        job->jobPrimitiveInputOutput.inputPtr,
                                        job->jobPrimitiveInputOutput.inputLength,
                                        job->jobPrimitiveInputOutput.outputPtr);
                                *(job->jobPrimitiveInputOutput.outputLengthPtr) =
                                MD5_BLOCK_SIZE;

                                ret = E_OK;
                            }
                        }
                    }
                }
                else
                {

#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                    Det_ReportError(CRYPTO_MODULE_ID, 0,
                    Crypto_ProcessJob_ID,
                                    CRYPTO_E_PARAM_HANDLE);
#endif
                    ret = E_NOT_OK;
                }
                /*SWS_Crypto_00067 satisfied*/
            }
        }
        else if (CRYPTO_ENCRYPT
                == (job->jobPrimitiveInfo->primitiveInfo->service))
        {

            if (NULL == (job->jobPrimitiveInputOutput.inputPtr))
            {
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00059 satisfied*/

            else if (0 == (job->jobPrimitiveInputOutput.inputLength))
            {
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
                ret = E_NOT_OK;

            }
            /*SWS_Crypto_00142 satisfied*/

            else if (NULL == (job->jobPrimitiveInputOutput.outputLengthPtr))
            {
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00059 satisfied*/
            else if (0 == *(job->jobPrimitiveInputOutput.outputLengthPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00142 satisfied*/
            else if (NULL == (job->jobPrimitiveInputOutput.outputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif
                ret = E_NOT_OK;

            }
            /*SWS_Crypto_00070 satisfied*/
            else
            {
                if (CRYPTO_ALGOFAM_3DES
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {
                    if (CRYPTO_ALGOMODE_CBC
                            == (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode))
                    {
                        if (Triple_Des_KEY_SIZE
                                == (job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength))
                        {
                            GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                                      (uint32*) &KeyIDx);

                            if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                            {
                                ret = CRYPTO_E_KEY_NOT_VALID;
                            }
                            else if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                                    < job->jobPrimitiveInputOutput.inputLength)
                            {
                                Det_ReportError(CRYPTO_MODULE_ID, 0,
                                Crypto_ProcessJob_ID,
                                                CRYPTO_E_RE_SMALL_BUFFER);
                                ret = CRYPTO_E_SMALL_BUFFER;
                            }
                            else
                            {
                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                {
                                    job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                                }

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_UPDATE)
                                {
                                    if (!((job->jobPrimitiveInputOutput.mode)
                                            & CRYPTO_OPERATIONMODE_START)
                                            && (CRYPTO_JOBSTATE_IDLE
                                                    == job->jobState))
                                    {
                                        ret = E_NOT_OK;
                                    }
                                    else
                                    {

                                    }
                                }

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_FINISH)
                                {
                                    if (!((job->jobPrimitiveInputOutput.mode)
                                            & CRYPTO_OPERATIONMODE_START)
                                            && (CRYPTO_JOBSTATE_IDLE
                                                    == job->jobState))
                                    {
                                        ret = E_NOT_OK;
                                    }
                                    else
                                    {
                                        GetKeyElementIDx(
                                                KeyElementsDataRef,
                                                1,
                                                (uint32*) &KeyElementIDx,
                                                KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                                KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                        GetKeyElementIDx(
                                                KeyElementsDataRef,
                                                5,
                                                (uint32*) &KeyElementIVIDx,
                                                KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                                KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                        Algo3DESEn_adaptor(
                                                job->jobPrimitiveInputOutput.inputPtr,
                                                job->jobPrimitiveInputOutput.inputLength,
                                                job->jobPrimitiveInputOutput.outputPtr,
                                                ElementsData,
                                                KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                                KeyElementsDataRef[KeyElementIVIDx].StartingByteIDx

                                                );
                                        ret = E_OK;

                                    }
                                    KeyElementIDx = 0;
                                    KeyIDx = 0;
                                    KeyElementIVIDx = 0;
                                }
                            }
                        }
                        else
                        {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                            Det_ReportError(CRYPTO_MODULE_ID, 0,
                            Crypto_ProcessJob_ID,
                                            CRYPTO_E_PARAM_HANDLE);
#endif
                            ret = E_NOT_OK;
                        }
                        /*SWS_Crypto_00067 satisfied*/

                    }

                    else
                    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_PARAM_HANDLE);
#endif
                        ret = E_NOT_OK;
                    }
                    /*SWS_Crypto_00067 satisfied*/
                }
                else if (CRYPTO_ALGOFAM_AES
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {
                    if (CRYPTO_ALGOMODE_CBC
                            == (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode))
                    {
                        if ((AES_KEY_SIZE_1
                                == (job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength))
                                | (AES_KEY_SIZE_2
                                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength))
                                | (AES_KEY_SIZE_3
                                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength)))
                        {
                            GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                                      (uint32*) &KeyIDx);

                            if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                            {
                                ret = CRYPTO_E_KEY_NOT_VALID;
                            }
                            else if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                                    < job->jobPrimitiveInputOutput.inputLength)
                            {
                                Det_ReportError(CRYPTO_MODULE_ID, 0,
                                Crypto_ProcessJob_ID,
                                                CRYPTO_E_RE_SMALL_BUFFER);
                                ret = CRYPTO_E_SMALL_BUFFER;
                            }
                            else
                            {

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                {
                                    job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                                }

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_UPDATE)
                                {
                                    if (!((job->jobPrimitiveInputOutput.mode)
                                            & CRYPTO_OPERATIONMODE_START)
                                            && (CRYPTO_JOBSTATE_IDLE
                                                    == job->jobState))
                                    {
                                        ret = E_NOT_OK;
                                    }
                                    else
                                    {

                                    }
                                }

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_FINISH)
                                {
                                    if (!((job->jobPrimitiveInputOutput.mode)
                                            & CRYPTO_OPERATIONMODE_START)
                                            && (CRYPTO_JOBSTATE_IDLE
                                                    == job->jobState))
                                    {
                                        ret = E_NOT_OK;
                                    }
                                    else
                                    {
                                        GetKeyElementIDx(
                                                KeyElementsDataRef,
                                                1,
                                                (uint32*) &KeyElementIDx,
                                                KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                                KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                        GetKeyElementIDx(
                                                KeyElementsDataRef,
                                                5,
                                                (uint32*) &KeyElementIVIDx,
                                                KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                                KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                        Algo_AesEn(
                                                job->jobPrimitiveInputOutput.inputPtr,
                                                job->jobPrimitiveInputOutput.inputLength,
                                                job->jobPrimitiveInputOutput.outputPtr,
                                                ElementsData,
                                                KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                                (job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength)
                                                        * 8,
                                                KeyElementsDataRef[KeyElementIVIDx].StartingByteIDx

                                                );
                                        ret = E_OK;

                                    }
                                    KeyElementIDx = 0;
                                    KeyIDx = 0;
                                    KeyElementIVIDx = 0;
                                }
                            }
                        }
                        else
                        {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                            Det_ReportError(CRYPTO_MODULE_ID, 0,
                            Crypto_ProcessJob_ID,
                                            CRYPTO_E_PARAM_HANDLE);
#endif
                            ret = E_NOT_OK;
                        }

                    }
                    else
                    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_PARAM_HANDLE);
#endif
                        ret = E_NOT_OK;
                    }
                    /*SWS_Crypto_00067 satisfied*/
                }
                else
                {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                    Det_ReportError(CRYPTO_MODULE_ID, 0,
                    Crypto_ProcessJob_ID,
                                    CRYPTO_E_PARAM_HANDLE);
#endif
                    ret = E_NOT_OK;
                }
                /*SWS_Crypto_00067 satisfied*/
            }
        }
        else if (CRYPTO_DECRYPT
                == (job->jobPrimitiveInfo->primitiveInfo->service))
        {

            if (NULL == (job->jobPrimitiveInputOutput.inputPtr))
            {
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00059 satisfied*/

            else if (0 == (job->jobPrimitiveInputOutput.inputLength))
            {
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00142 satisfied*/

            else if (NULL == (job->jobPrimitiveInputOutput.outputLengthPtr))
            {
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00059 satisfied*/
            else if (0 == *(job->jobPrimitiveInputOutput.outputLengthPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00142 satisfied*/
            else if (NULL == (job->jobPrimitiveInputOutput.outputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif
                ret = E_NOT_OK;

            }
            /*SWS_Crypto_00070 satisfied*/
            else
            {
                if (CRYPTO_ALGOFAM_3DES
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {
                    if (CRYPTO_ALGOMODE_CBC
                            == (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode))
                    {
                        GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                                  (uint32*) &KeyIDx);

                        if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                        {
                            ret = CRYPTO_E_KEY_NOT_VALID;

                        }
                        else if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                                < job->jobPrimitiveInputOutput.inputLength)
                        {
                            Det_ReportError(CRYPTO_MODULE_ID, 0,
                            Crypto_ProcessJob_ID,
                                            CRYPTO_E_RE_SMALL_BUFFER);
                            ret = CRYPTO_E_SMALL_BUFFER;
                        }
                        else
                        {
                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                            {
                                job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                            }

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_UPDATE)
                            {
                                if (!((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                        && (CRYPTO_JOBSTATE_IDLE
                                                == job->jobState))
                                {
                                    ret = E_NOT_OK;
                                }
                                else
                                {

                                }
                            }

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_FINISH)
                            {
                                if (!((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                        && (CRYPTO_JOBSTATE_IDLE
                                                == job->jobState))
                                {
                                    ret = E_NOT_OK;
                                }
                                else
                                {
                                    GetKeyElementIDx(
                                            KeyElementsDataRef,
                                            1,
                                            (uint32*) &KeyElementIDx,
                                            KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                            KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                    GetKeyElementIDx(
                                            KeyElementsDataRef,
                                            5,
                                            (uint32*) &KeyElementIVIDx,
                                            KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                            KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                    Algo3DESDe_adaptor(
                                            job->jobPrimitiveInputOutput.inputPtr,
                                            job->jobPrimitiveInputOutput.inputLength,
                                            job->jobPrimitiveInputOutput.outputPtr,
                                            ElementsData,
                                            KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                            KeyElementsDataRef[KeyElementIVIDx].StartingByteIDx

                                            );
                                    ret = E_OK;

                                }
                                KeyElementIDx = 0;
                                KeyIDx = 0;
                                KeyElementIVIDx = 0;

                            }
                        }

                    }
                    else
                    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_PARAM_HANDLE);
#endif
                        ret = E_NOT_OK;
                    }
                    /*SWS_Crypto_00067 satisfied*/
                }
                else if (CRYPTO_ALGOFAM_AES
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                {
                    if (CRYPTO_ALGOMODE_CBC
                            == (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode))
                    {
                        GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                                  (uint32*) &KeyIDx);
                        if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                        {
                            ret = CRYPTO_E_KEY_NOT_VALID;
                        }
                        else if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                                < job->jobPrimitiveInputOutput.inputLength)
                        {
                            Det_ReportError(CRYPTO_MODULE_ID, 0,
                            Crypto_ProcessJob_ID,
                                            CRYPTO_E_RE_SMALL_BUFFER);
                            ret = CRYPTO_E_SMALL_BUFFER;
                        }
                        else
                        {
                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                            {
                                job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                            }

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_UPDATE)
                            {
                                if (!((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                        && (CRYPTO_JOBSTATE_IDLE
                                                == job->jobState))
                                {
                                    ret = E_NOT_OK;
                                }
                                else
                                {

                                }
                            }

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_FINISH)
                            {
                                if (!((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                        && (CRYPTO_JOBSTATE_IDLE
                                                == job->jobState))
                                {
                                    ret = E_NOT_OK;
                                }

                                else
                                {
                                    GetKeyElementIDx(
                                            KeyElementsDataRef,
                                            1,
                                            (uint32*) &KeyElementIDx,
                                            KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                            KeyElementRef[KeyIDx].KeyElementEndingIDx);
                                    GetKeyElementIDx(
                                            KeyElementsDataRef,
                                            5,
                                            (uint32*) &KeyElementIVIDx,
                                            KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                            KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                    Algo_AesDe(
                                            job->jobPrimitiveInputOutput.inputPtr,
                                            job->jobPrimitiveInputOutput.inputLength,
                                            job->jobPrimitiveInputOutput.outputPtr,
                                            ElementsData,
                                            KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                            (job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength)
                                                    * 8,
                                            KeyElementsDataRef[KeyElementIVIDx].StartingByteIDx

                                            );
                                    ret = E_OK;
                                }
                                KeyElementIDx = 0;
                                KeyIDx = 0;
                                KeyElementIVIDx = 0;

                            }
                        }
                    }
                    else
                    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_PARAM_HANDLE);
#endif
                        ret = E_NOT_OK;
                    }
                    /*SWS_Crypto_00067 satisfied*/
                }

                else
                {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                    Det_ReportError(CRYPTO_MODULE_ID, 0,
                    Crypto_ProcessJob_ID,
                                    CRYPTO_E_PARAM_HANDLE);
#endif
                    ret = E_NOT_OK;
                }
                /*SWS_Crypto_00067 satisfied*/
            }
        }
        else if (CRYPTO_RANDOMGENERATE
                == (job->jobPrimitiveInfo->primitiveInfo->service))
        {
            if (NULL == (job->jobPrimitiveInputOutput.outputLengthPtr))
            {
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00059 satisfied*/
            else if (0 == *(job->jobPrimitiveInputOutput.outputLengthPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00142 satisfied*/
            else if (NULL == (job->jobPrimitiveInputOutput.outputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif
                ret = E_NOT_OK;

            }
            /*SWS_Crypto_00070 satisfied*/
            else
            {
                if (CRYPTO_ALGOFAM_RNG
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))

                {
                    GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                              (uint32*) &KeyIDx);
                    if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                    {
                        ret = CRYPTO_E_KEY_NOT_VALID;
                    }
                    else if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                            < PCG_Generated_Number_Length)
                    {
                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_RE_SMALL_BUFFER);
                        ret = CRYPTO_E_SMALL_BUFFER;
                    }

                    else
                    {
                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_START)
                        {
                            job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_UPDATE)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {

                            }
                        }

                        if ((job->jobPrimitiveInputOutput.mode)
                                & CRYPTO_OPERATIONMODE_FINISH)
                        {
                            if (!((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                                    && (CRYPTO_JOBSTATE_IDLE == job->jobState))
                            {
                                ret = E_NOT_OK;
                            }
                            else
                            {
                                GetKeyElementIDx(
                                        KeyElementsDataRef,
                                        3,
                                        (uint32*) &KeyElementIDx,
                                        KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                        KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                Algo32RNG_adaptor(
                                        job->jobPrimitiveInputOutput.outputPtr,
                                        job->jobPrimitiveInputOutput.outputLengthPtr,
                                        ElementsData,
                                        KeyElementsDataRef[KeyElementIDx].StartingByteIDx);
                                KeyElementIDx = 0;
                                KeyIDx = 0;
                                ret = E_OK;
                            }
                        }
                    }
                }
                else
                {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                    Det_ReportError(CRYPTO_MODULE_ID, 0,
                    Crypto_ProcessJob_ID,
                                    CRYPTO_E_PARAM_HANDLE);
#endif
                    ret = E_NOT_OK;
                }
                /*SWS_Crypto_00067 satisfied*/
            }
        }

        else if (CRYPTO_MACGENERATE
                == (job->jobPrimitiveInfo->primitiveInfo->service))
        {
            if (NULL == (job->jobPrimitiveInputOutput.inputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif

                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00059 satisfied*/

            else if (0 == (job->jobPrimitiveInputOutput.inputLength))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00142 satisfied*/

            else if (NULL == (job->jobPrimitiveInputOutput.outputLengthPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif
                ret = E_NOT_OK;
            }

            /*SWS_Crypto_00059 satisfied*/

            else if (0 == *(job->jobPrimitiveInputOutput.outputLengthPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00142 satisfied*/
            else if (NULL == (job->jobPrimitiveInputOutput.outputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif
                ret = E_NOT_OK;

            }
            /*SWS_Crypto_00070 satisfied*/
            else
            {
                if (CRYPTO_ALGOMODE_HMAC
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode))
                {

                    //job->jobPrimitiveInfo->
                    if (CRYPTO_ALGOFAM_SHA1
                            == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))

                    {

                        GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                                  (uint32*) &KeyIDx);
                        if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                        {
                            ret = CRYPTO_E_KEY_NOT_VALID;
                        }
                        else if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                                < SHA1_BLOCK_SIZE)
                        {
                            Det_ReportError(CRYPTO_MODULE_ID, 0,
                            Crypto_ProcessJob_ID,
                                            CRYPTO_E_RE_SMALL_BUFFER);
                            ret = CRYPTO_E_SMALL_BUFFER;
                        }

                        else
                        {
                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                            {
                                job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                            }

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_UPDATE)
                            {
                                if (!((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                        && (CRYPTO_JOBSTATE_IDLE
                                                == job->jobState))
                                {
                                    ret = E_NOT_OK;
                                }
                                else
                                {

                                }
                            }

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_FINISH)
                            {
                                if (!((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                        && (CRYPTO_JOBSTATE_IDLE
                                                == job->jobState))
                                {
                                    ret = E_NOT_OK;
                                }
                                else
                                {

                                    GetKeyElementIDx(
                                            KeyElementsDataRef,
                                            1,
                                            (uint32*) &KeyElementIDx, //macKey
                                            KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                            KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                    Algo_HMAC_SHA1_adaptor(
                                            job->jobPrimitiveInputOutput.inputPtr,
                                            job->jobPrimitiveInputOutput.inputLength,
                                            job->jobPrimitiveInputOutput.outputPtr,
                                            ElementsData,
                                            KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                            job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength

                                            );
                                    ret = E_OK;

                                }
                                KeyElementIDx = 0;
                                KeyIDx = 0;
                            }
                        }

                    }
                    else
                    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_PARAM_HANDLE);
#endif
                        ret = E_NOT_OK;
                    }
                    /*SWS_Crypto_00067 satisfied*/
                }
                else if (CRYPTO_ALGOMODE_CMAC
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode))
                {

                    if (CRYPTO_ALGOFAM_AES
                            == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                    {
                        if (CMAC_AES_KEY_SIZE
                                == (job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength))
                        {
                            GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                                      (uint32*) &KeyIDx);

                            if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                            {
                                ret = CRYPTO_E_KEY_NOT_VALID;
                            }
                            else if (*(job->jobPrimitiveInputOutput.outputLengthPtr)
                                    < AES_BLOCK_SIZE)
                            {
                                Det_ReportError(CRYPTO_MODULE_ID, 0,
                                Crypto_ProcessJob_ID,
                                                CRYPTO_E_RE_SMALL_BUFFER);
                                ret = CRYPTO_E_SMALL_BUFFER;
                            }
                            else
                            {

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                {
                                    job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                                }

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_UPDATE)
                                {
                                    if (!((job->jobPrimitiveInputOutput.mode)
                                            & CRYPTO_OPERATIONMODE_START)
                                            && (CRYPTO_JOBSTATE_IDLE
                                                    == job->jobState))
                                    {
                                        ret = E_NOT_OK;
                                    }
                                    else
                                    {

                                    }
                                }

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_FINISH)
                                {
                                    if (!((job->jobPrimitiveInputOutput.mode)
                                            & CRYPTO_OPERATIONMODE_START)
                                            && (CRYPTO_JOBSTATE_IDLE
                                                    == job->jobState))
                                    {
                                        ret = E_NOT_OK;
                                    }
                                    else
                                    {

                                        GetKeyElementIDx(
                                                KeyElementsDataRef,
                                                1,
                                                (uint32*) &KeyElementIDx, //macKey
                                                KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                                KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                        Algo_CMAC_AES_adaptor(
                                                job->jobPrimitiveInputOutput.inputPtr,
                                                job->jobPrimitiveInputOutput.inputLength,
                                                job->jobPrimitiveInputOutput.outputPtr,
                                                ElementsData,
                                                KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                                job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength

                                                );
                                        ret = E_OK;
                                    }
                                    KeyElementIDx = 0;
                                    KeyIDx = 0;
                                }
                            }
                        }
                        else
                        {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                            Det_ReportError(CRYPTO_MODULE_ID, 0,
                            Crypto_ProcessJob_ID,
                                            CRYPTO_E_PARAM_HANDLE);
#endif
                            ret = E_NOT_OK;
                        }
                    }
                    else
                    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_PARAM_HANDLE);
#endif
                        ret = E_NOT_OK;
                    }
                    /*SWS_Crypto_00067 satisfied*/
                }
                else
                {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                    Det_ReportError(CRYPTO_MODULE_ID, 0,
                    Crypto_ProcessJob_ID,
                                    CRYPTO_E_PARAM_HANDLE);
#endif
                    ret = E_NOT_OK;
                }
                /*SWS_Crypto_00067 satisfied*/
            }
        }

        else if (CRYPTO_MACVERIFY
                == (job->jobPrimitiveInfo->primitiveInfo->service))
        {
            if (NULL == (job->jobPrimitiveInputOutput.inputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif

                ret = E_NOT_OK;
            }
            else if (NULL == (job->jobPrimitiveInputOutput.secondaryInputPtr))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_POINTER);
#endif

                ret = E_NOT_OK;
            }
            /*SWS_Crypto_00059 satisfied*/

            else if (0 == (job->jobPrimitiveInputOutput.inputLength))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }
            else if (0 == (job->jobPrimitiveInputOutput.secondaryInputLength))
            {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_ProcessJob_ID,
                                CRYPTO_E_PARAM_VALUE);
#endif
                ret = E_NOT_OK;
            }

            else
            {
                if (CRYPTO_ALGOMODE_HMAC
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode))
                {

                    if (CRYPTO_ALGOFAM_SHA1
                            == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))

                    {

                        GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                                  (uint32*) &KeyIDx);
                        if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                        {
                            ret = CRYPTO_E_KEY_NOT_VALID;
                        }

                        else
                        {

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_START)
                            {
                                job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                            }

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_UPDATE)
                            {
                                if (!((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                        && (CRYPTO_JOBSTATE_IDLE
                                                == job->jobState))
                                {
                                    ret = E_NOT_OK;
                                }
                                else
                                {

                                }
                            }

                            if ((job->jobPrimitiveInputOutput.mode)
                                    & CRYPTO_OPERATIONMODE_FINISH)
                            {
                                if (!((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                        && (CRYPTO_JOBSTATE_IDLE
                                                == job->jobState))
                                {
                                    ret = E_NOT_OK;
                                }
                                else
                                {

                                    GetKeyElementIDx(
                                            KeyElementsDataRef,
                                            1,
                                            (uint32*) &KeyElementIDx, //macKey
                                            KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                            KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                    Algo_HMAC_SHA1_adaptor(
                                            job->jobPrimitiveInputOutput.inputPtr,
                                            job->jobPrimitiveInputOutput.inputLength,
                                            verifyArr,
                                            ElementsData,
                                            KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                            job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength

                                            );
                                    KeyElementIDx = 0;
                                    KeyIDx = 0;

                                    checkMac =
                                            sameMac(job->jobPrimitiveInputOutput.secondaryInputPtr,
                                                    verifyArr,
                                                    job->jobPrimitiveInputOutput.secondaryInputLength);

                                    if (checkMac == TRUE)
                                    {
                                        *(job->jobPrimitiveInputOutput.verifyPtr) =
                                                CRYPTO_E_VER_OK;
                                    }
                                    else
                                    {
                                        *(job->jobPrimitiveInputOutput.verifyPtr) =
                                                CRYPTO_E_VER_NOT_OK;
                                    }
                                    ret = E_OK;
                                }
                            }

                        }

                    }
                    else
                    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_PARAM_HANDLE);
#endif
                        ret = E_NOT_OK;
                    }
                    /*SWS_Crypto_00067 satisfied*/
                }
                else if (CRYPTO_ALGOMODE_CMAC
                        == (job->jobPrimitiveInfo->primitiveInfo->algorithm.mode))
                {
                    if (CRYPTO_ALGOFAM_AES
                            == (job->jobPrimitiveInfo->primitiveInfo->algorithm.family))
                    {
                        if (CMAC_AES_KEY_SIZE
                                == (job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength))
                        {
                            GetKeyIDx(KeyElementRef, job->cryptoKeyId,
                                      (uint32*) &KeyIDx);

                            if (FALSE == KeyElementRef[KeyIDx].KeyValidity)
                            {
                                ret = CRYPTO_E_KEY_NOT_VALID;
                            }

                            else
                            {

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_START)
                                {
                                    job->jobState = CRYPTO_JOBSTATE_ACTIVE;

                                }

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_UPDATE)
                                {
                                    if (!((job->jobPrimitiveInputOutput.mode)
                                            & CRYPTO_OPERATIONMODE_START)
                                            && (CRYPTO_JOBSTATE_IDLE
                                                    == job->jobState))
                                    {
                                        ret = E_NOT_OK;
                                    }
                                    else
                                    {

                                    }
                                }

                                if ((job->jobPrimitiveInputOutput.mode)
                                        & CRYPTO_OPERATIONMODE_FINISH)
                                {
                                    if (!((job->jobPrimitiveInputOutput.mode)
                                            & CRYPTO_OPERATIONMODE_START)
                                            && (CRYPTO_JOBSTATE_IDLE
                                                    == job->jobState))
                                    {
                                        ret = E_NOT_OK;
                                    }
                                    else
                                    {

                                        GetKeyElementIDx(
                                                KeyElementsDataRef,
                                                1,
                                                (uint32*) &KeyElementIDx, //macKey
                                                KeyElementRef[KeyIDx].KeyElementStartingIDx,
                                                KeyElementRef[KeyIDx].KeyElementEndingIDx);

                                        Algo_CMAC_AES_adaptor(
                                                job->jobPrimitiveInputOutput.inputPtr,
                                                job->jobPrimitiveInputOutput.inputLength,
                                                verifyArr,
                                                ElementsData,
                                                KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                                job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength

                                                );
                                        KeyElementIDx = 0;
                                        KeyIDx = 0;
                                        checkMac =
                                                sameMac(job->jobPrimitiveInputOutput.secondaryInputPtr,
                                                        verifyArr,
                                                        job->jobPrimitiveInputOutput.secondaryInputLength);

                                        if (checkMac == TRUE)
                                        {
                                            *(job->jobPrimitiveInputOutput.verifyPtr) =
                                                    CRYPTO_E_VER_OK;
                                        }
                                        else
                                        {
                                            *(job->jobPrimitiveInputOutput.verifyPtr) =
                                                    CRYPTO_E_VER_NOT_OK;
                                        }
                                        ret = E_OK;
                                    }
                                }
                            }
                        }
                        else
                        {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                            Det_ReportError(CRYPTO_MODULE_ID, 0,
                            Crypto_ProcessJob_ID,
                                            CRYPTO_E_PARAM_HANDLE);
#endif
                            ret = E_NOT_OK;
                        }
                    }
                    else
                    {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                        Det_ReportError(CRYPTO_MODULE_ID, 0,
                        Crypto_ProcessJob_ID,
                                        CRYPTO_E_PARAM_HANDLE);
#endif
                        ret = E_NOT_OK;
                    }
                    /*SWS_Crypto_00067 satisfied*/
                }
                else
                {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)

                    Det_ReportError(CRYPTO_MODULE_ID, 0,
                    Crypto_ProcessJob_ID,
                                    CRYPTO_E_PARAM_HANDLE);
#endif
                    ret = E_NOT_OK;
                }
                /*SWS_Crypto_00067 satisfied*/
            }
        }
        else
        {
#if (STD_ON==CRYPTO_DEV_ERROR_DETECT)
            Det_ReportError(CRYPTO_MODULE_ID, 0,
            Crypto_ProcessJob_ID,
                            CRYPTO_E_PARAM_HANDLE);
#endif
            ret = E_NOT_OK;
            /*SWS_Crypto_00064 satisfied*/

        }
    }

    return ret;

}
/*Job Cancellation Interface*/

/**********************************************************************************************************************
 *  Crypto_CancelJob()
 *********************************************************************************************************************/
/*! \brief         This interface removes the provided job from the queue and cancels the processing of the job if possible.
 *  \param[in]     objectId                Holds the identifier of the Crypto Driver Object.
 *  \param[in,out] job                     Pointer to the configuration of the job. Contains structures with user and
 *                                         primitive relevant information.
 *  \return        E_OK                    Request successful, job has been removed
 *  \return        E_NOT_OK                Request Failed, job couldn't be removed.
 *  \return        CRYPTO_E_JOB_CANCELED   The job has been cancelled but is still processed. No results will be returned to the application.
 *  \reentrant     Reentrant, but not for same Crypto Driver Object
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType Crypto_CancelJob(uint32 objectId, Crypto_JobInfoType *job)
{
    Std_ReturnType ret = E_NOT_OK;

    if (FALSE == Cryptoinit)
    {

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_ProcessJob_ID,
                        CRYPTO_E_UNINIT);
        ret = E_NOT_OK;

    }
    /*SWS_Crypto_00123 satisfied*/

    else if (NULL == job)
    {
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_ProcessJob_ID,
                        CRYPTO_E_PARAM_POINTER);
        ret = E_NOT_OK;
    }
    /*SWS_Crypto_00125 satisfied*/

    else if (objectId > Objects)
    {
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_ProcessJob_ID,
                        CRYPTO_E_PARAM_HANDLE);
        ret = E_NOT_OK;
    }
    /*SWS_Crypto_00124 satisfied*/
    else
    {
        ret = CRYPTO_E_JOB_CANCELED;
    }
    return ret;
}

/**********************************************************************************************************************
 *  Crypto_KeyElementSet()
 *********************************************************************************************************************/
/*! \brief         Sets the given key element bytes to the key identified by cryptoKeyId.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose key element shall be set.
 *  \param[in]     keyElementId            Holds the identifier of the key element which shall be set.
 *  \param[in]     keyPtr                  Holds the pointer to the key data which shall be set as key element.
 *  \param[in]     keyLength               Contains the length of the key element in bytes.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed because write access was denied
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE Request failed because the key is not available.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, key element size does not match size of provided data.
 *  \reentrant     FALSE
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType Crypto_KeyElementSet(uint32 cryptoKeyId, uint32 keyElementId,
                                    const uint8 *keyPtr, uint32 keyLength)
{

    Std_ReturnType ret = E_NOT_OK;
    uint32 KeyIDx = 0;
    uint32 KeyElementIDx = 0;
    boolean keyflag = FALSE;
    boolean keyelementflag = FALSE;
    if (FALSE == Cryptoinit)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementSet_ID,
                        CRYPTO_E_UNINIT);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00075 satisfied*/

    }

    else if (NULL == keyPtr)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementSet_ID,
                        CRYPTO_E_PARAM_POINTER);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00078*/

    }
    else if (0 == keyLength)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementSet_ID,
                        CRYPTO_E_PARAM_VALUE);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00079 satisfied*/

    }
    else
    {

        keyflag = GetKeyIDx(KeyElementRef, cryptoKeyId, (uint32*) &KeyIDx);
        if (FALSE == keyflag)
        {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

            Det_ReportError(CRYPTO_MODULE_ID, 0,
            Crypto_KeyElementSet_ID,
                            CRYPTO_E_PARAM_HANDLE);
#endif
            ret = E_NOT_OK;
            /*SWS_Crypto_00076 satisfied*/

        }
        else if (TRUE == keyflag)
        {
            keyelementflag = GetKeyElementIDx(
                    KeyElementsDataRef, keyElementId, (uint32*) &KeyElementIDx,
                    KeyElementRef[KeyIDx].KeyElementStartingIDx, keyLength);
            if (FALSE == keyelementflag)
            {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_KeyElementSet_ID,
                                CRYPTO_E_PARAM_HANDLE);
#endif
                ret = E_NOT_OK;
                /*SWS_Crypto_00077 satisfied*/

            }
            else if (TRUE == keyelementflag)
            {
                if (CRYPTO_WA_DENIED
                        == KeyElementsCfg[KeyElementIDx].CryptoKeyElementWriteAccess)
                {
                    ret = CRYPTO_E_KEY_WRITE_FAIL;
                }
                else if (CRYPTO_WA_ALLOWED
                        == KeyElementsCfg[KeyElementIDx].CryptoKeyElementWriteAccess)
                {
                    if (keyLength
                            < KeyElementsCfg[KeyElementIDx].CryptoKeyElementSize)
                    {
                        if (TRUE
                                == KeyElementsCfg[KeyElementIDx].CryptoKeyElementAllowPartialAccess)
                        {
                            SetElementData(
                                    ElementsData,
                                    keyPtr,
                                    KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                    keyLength);
                            ret = E_OK;
                            KeyElementRef[KeyIDx].KeyValidity = FALSE;
                            /*SWS_Crypto_00146 Satisfied*/
                        }
                        else if (FALSE
                                == KeyElementsCfg[KeyElementIDx].CryptoKeyElementAllowPartialAccess)
                        {
                            ret = CRYPTO_E_KEY_SIZE_MISMATCH;
                        }

                    }
                    /*SWS_Crypto_00146 Satisfied*/

                    else
                    {
                        SetElementData(
                                ElementsData,
                                keyPtr,
                                KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                keyLength);
                        ret = E_OK;
                        KeyElementRef[KeyIDx].KeyValidity = FALSE;

                    }
                }
            }
        }
    }

    return ret;

}

/**********************************************************************************************************************
 *  Crypto_KeySetValid()
 *********************************************************************************************************************/
/*! \brief         Sets the key state of the key identified by cryptoKeyId to valid.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be set to valid.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE
 *  \synchronous   FALSE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeySetValid(uint32 cryptoKeyId)
{
    Std_ReturnType ret = E_NOT_OK;
    uint32 KeyIDx = 0;
    boolean keyflag = FALSE;
    if (FALSE == Cryptoinit)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeySetValid_ID,
                        CRYPTO_E_UNINIT);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00085 satisfied*/

    }
    else
    {
        keyflag = GetKeyIDx(KeyElementRef, cryptoKeyId, (uint32*) &KeyIDx);
    }

    if (FALSE == keyflag)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeySetValid_ID,
                        CRYPTO_E_PARAM_HANDLE);
#endif
        ret = E_NOT_OK;
    }
    else
    {
        KeyElementRef[KeyIDx].KeyValidity = TRUE;
        ret = E_OK;

    }

    return ret;

}

/*Key Extraction Interface*/

/**********************************************************************************************************************
 *  Crypto_KeyElementGet()
 *********************************************************************************************************************/
/*! \brief         This interface shall be used to get a key element of the key identified by the cryptoKeyId and
 store the key element in the memory location pointed by the result pointer.
 If the actual key element is directly mapped to flash memory, there could be a bigger delay
 when calling this function (synchronous operation).
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose key element shall be returned.
 *  \param[in]     keyElementId            Holds the identifier of the key element which shall be returned.
 *  \param[in,out] resultLengthPtr         Holds a pointer to a memory location in which the length information is stored.
 *                                         On calling this function this parameter shall contain the size of the buffer provided by resultPtr.
 *                                         If the key element is configured to allow partial access,
 *                                         this parameter contains the amount of data which should be read from the key element.
 *                                         The size may not be equal to the size of the provided buffer anymore.
 *                                         When the request has finished, the amount of data that has been stored shall be stored.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE Request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \reentrant     TRUE
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyElementGet(uint32 cryptoKeyId, uint32 keyElementId,
                                    uint8 *resultPtr, uint32 *resultLengthPtr)
{

    Std_ReturnType ret = E_NOT_OK;
    uint32 KeyIDx = 0;
    uint32 KeyElementIDx = 0;
    boolean keyflag = FALSE;
    boolean keyelementflag = FALSE;
    if (FALSE == Cryptoinit)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementGet_ID,
                        CRYPTO_E_UNINIT);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00085 satisfied*/

    }

    else if (NULL == resultPtr)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementGet_ID,
                        CRYPTO_E_PARAM_POINTER);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00088 satisfied*/

    }
    else if (NULL == resultLengthPtr)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementGet_ID,
                        CRYPTO_E_PARAM_POINTER);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00089 satisfied*/

    }
    else if (0 == *resultLengthPtr)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementGet_ID,
                        CRYPTO_E_PARAM_VALUE);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00090 satisfied*/

    }
    else
    {

        keyflag = GetKeyIDx(KeyElementRef, cryptoKeyId, (uint32*) &KeyIDx);
        if (FALSE == keyflag)
        {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

            Det_ReportError(CRYPTO_MODULE_ID, 0,
            Crypto_KeyElementGet_ID,
                            CRYPTO_E_PARAM_HANDLE);
#endif
            ret = E_NOT_OK;
            /*SWS_Crypto_00086 satisfied*/

        }
        else if (TRUE == keyflag)
        {
            keyelementflag = GetKeyElementIDx(
                    KeyElementsDataRef, keyElementId, (uint32*) &KeyElementIDx,
                    KeyElementRef[KeyIDx].KeyElementStartingIDx,
                    KeyElementRef[KeyIDx].KeyElementEndingIDx);
            if (FALSE == keyelementflag)
            {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_KeyElementGet_ID,
                                CRYPTO_E_PARAM_HANDLE);
#endif
                ret = E_NOT_OK;
                /*SWS_Crypto_00087 satisfied*/

            }
            else if (TRUE == keyelementflag)
            {
                if (CRYPTO_RA_DENIED
                        == KeyElementsCfg[KeyElementIDx].CryptoKeyElementReadAccess)
                {
                    ret = CRYPTO_E_KEY_READ_FAIL;
                }
                else if (CRYPTO_RA_ALLOWED
                        == KeyElementsCfg[KeyElementIDx].CryptoKeyElementReadAccess)
                {
                    if (*resultLengthPtr
                            < KeyElementsCfg[KeyElementIDx].CryptoKeyElementSize)
                    {
                        ret = CRYPTO_E_SMALL_BUFFER;
                    }
                    else
                    {
                        GetElementData(
                                ElementsData,
                                resultPtr,
                                KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                                KeyElementsCfg[KeyElementIDx].CryptoKeyElementSize);
                        *resultLengthPtr =
                                KeyElementsCfg[KeyElementIDx].CryptoKeyElementSize;
                        ret = E_OK;

                    }

                }
            }
        }
    }

    return ret;

}

/*Key Copying Interface*/

/**********************************************************************************************************************
 *  Crypto_KeyElementCopy()
 *********************************************************************************************************************/
/*! \brief         Copies a key element to another key element in the same crypto driver.
 *                 If the actual key element is directly mapped to flash memory,
 *                 there could be a bigger delay when calling this function (synchronous operation)
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose key element shall be the source element.
 *  \param[in]     keyElementId            Holds the identifier of the key element which shall be the source for the copy operation.
 *  \param[in]     targetCryptoKeyId       Holds the identifier of the key whose key element shall be the destination element.
 *  \param[in]     targetKeyElementId      Holds the identifier of the key element which shall be the destination for the copy operation.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE Request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed, not allowed to write key element.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, key element sizes are not compatible.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyElementCopy(uint32 cryptoKeyId, uint32 keyElementId,
                                     uint32 targetCryptoKeyId,
                                     uint32 targetKeyElementId)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}

/**********************************************************************************************************************
 *  Crypto_KeyCopy()
 *********************************************************************************************************************/
/*! \brief         Copies a key with all its elements to another key in the same crypto driver.
 *                 If the actual key element is directly mapped to flash memory,
 *                 there could be a bigger delay when calling this function (synchronous operation)
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose key element shall be the source element
 *  \param[in]     targetCryptoKeyId       Holds the identifier of the key whose key element shall be the destination element.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_KEY_NOT_AVAILABLE Request failed, the requested key element is not available
 *  \return        CRYPTO_E_KEY_READ_FAIL Request failed because read access was denied
 *  \return        CRYPTO_E_KEY_WRITE_FAIL Request failed, not allowed to write key element.
 *  \return        CRYPTO_E_KEY_SIZE_MISMATCH Request failed, key element sizes are not compatible.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyCopy(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}

/**********************************************************************************************************************
 *  Crypto_KeyElementIdsGet()
 *********************************************************************************************************************/
/*! \brief         Used to retrieve information which key elements are available in a given key.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key whose available element ids shall be exported.
 *  \param[in]     keyElementIdsLengthPtr  Holds a pointer to the memory location in which the number of key elements in the given key is stored.
 *                                         On calling this function, this parameter shall contain the size of the buffer provided by keyElementIdsPtr.
 *                                         When the request has finished, the actual number of key elements shall be stored.
 *  \param[out]    keyElementIdsPtr        Contains the pointer to the array where the ids of the key elements shall be stored.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_SMALL_BUFFER   The provided buffer is too small to store the result
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyElementIdsGet(uint32 cryptoKeyId,
                                       uint32 *keyElementIdsPtr,
                                       uint32 *keyElementIdsLengthPtr)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}
/*Key Generation Interface*/

/**********************************************************************************************************************
 *  Crypto_RandomSeed()
 *********************************************************************************************************************/
/*! \brief         This function generates the internal seed state using the provided entropy source.
 *                 Furthermore, this function can be used to update the seed state with new entropy
 *  \param[in]     cryptoKeyId             Holds the identifier of the key for which a new seed shall be generated.
 *  \param[in]     seedPtr                 Holds a pointer to the memory location which contains the data to feed the seed.
 *  \param[in]     seedLength              Contains the length of the seed in bytes.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_RandomSeed(uint32 cryptoKeyId, const uint8 *seedPtr,
                                 uint32 seedLength)
{
    Std_ReturnType ret = E_NOT_OK;
    uint32 KeyIDx = 0;
    uint32 KeyElementIDx = 0;
    boolean keyflag = FALSE;
    boolean keyelementflag = FALSE;
    if (FALSE == Cryptoinit)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementSet_ID,
                        CRYPTO_E_UNINIT);
#endif
        ret = E_NOT_OK;

    }

    else if (NULL == seedPtr)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementSet_ID,
                        CRYPTO_E_PARAM_POINTER);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00078*/

    }
    else if (0 == seedLength)
    {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

        Det_ReportError(CRYPTO_MODULE_ID, 0,
        Crypto_KeyElementSet_ID,
                        CRYPTO_E_PARAM_VALUE);
#endif
        ret = E_NOT_OK;
        /*SWS_Crypto_00079 satisfied*/

    }
    else
    {
        keyflag = GetKeyIDx(KeyElementRef, cryptoKeyId, (uint32*) &KeyIDx);
        if (FALSE == keyflag)
        {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

            Det_ReportError(CRYPTO_MODULE_ID, 0,
            Crypto_KeyElementGet_ID,
                            CRYPTO_E_PARAM_HANDLE);
#endif
            ret = E_NOT_OK;
            /*SWS_Crypto_00086 satisfied*/

        }
        else if (TRUE == keyflag)
        {
            keyelementflag = GetKeyElementIDx(
                    KeyElementsDataRef, 0x03, (uint32*) &KeyElementIDx,
                    KeyElementRef[KeyIDx].KeyElementStartingIDx,
                    KeyElementRef[KeyIDx].KeyElementEndingIDx);
            if (FALSE == keyelementflag)
            {
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)

                Det_ReportError(CRYPTO_MODULE_ID, 0,
                Crypto_KeyElementGet_ID,
                                CRYPTO_E_PARAM_HANDLE);
#endif
                ret = E_NOT_OK;

            }
            else
            {
                SetElementData(
                        ElementsData, seedPtr,
                        KeyElementsDataRef[KeyElementIDx].StartingByteIDx,
                        seedLength);
                KeyElementRef[KeyIDx].KeyValidity = FALSE;
                ret = E_OK;
            }
        }
    }
    return ret;

}

/**********************************************************************************************************************
 *  Crypto_KeyGenerate()
 *********************************************************************************************************************/
/*! \brief         Generates new key material store it in the key identified by cryptoKeyId.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which is to be updated with the generated value.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyGenerate(uint32 cryptoKeyId)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}

/*Key Derivation Interface*/

/**********************************************************************************************************************
 *  Crypto_KeyDerive()
 *********************************************************************************************************************/
/*! \brief         Derives a new key by using the key elements in the given key identified by the cryptoKeyId.
 *                 The given key contains the key elements for the password, salt.
 *                 The derived key is stored in the key element with the id 1 of the key identified by targetCryptoKeyId.
 *                 The number of iterations is given in the key element CRYPTO_KE_KEYDERIVATION_ITERATIONS.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which is used for key derivation.
 *  \param[in]     targetCryptoKeyId       Holds the identifier of the key which is used to store the derived key.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyDerive(uint32 cryptoKeyId, uint32 targetCryptoKeyId)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}
/*Key Exchange Interface*/

/**********************************************************************************************************************
 *  Crypto_KeyExchangeCalcPubVal()
 *********************************************************************************************************************/
/*! \brief         Calculates the public value for the key exchange
 *                 and stores the public key in the memory location pointed by the public value pointer.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be used for the key exchange protocol.
 *  \param[in,out] publicValueLengthPtr    Holds a pointer to the memory location in which the public value length information is stored.
 *                                         On calling this function, this parameter shall contain the size of the buffer provided by publicValuePtr.
 *                                         When the request has finished, the actual length of the returned value shall be stored.
 *  \param[out]    publicValuePtr          Contains the pointer to the data where the public value shall be stored.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyExchangeCalcPubVal(uint32 cryptoKeyId,
                                            uint8 *publicValuePtr,
                                            uint32 *publicValueLengthPtr)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}

/**********************************************************************************************************************
 *  Crypto_KeyExchangeCalcSecret()
 *********************************************************************************************************************/
/*! \brief         Calculates the shared secret key for the key exchange with the key material of the key identified by the cryptoKeyId and the partner public key.
 *                 The shared secret key is stored as a key element in the same key.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be used for the key exchange protocol.
 *  \param[in]     partnerPublicValuePtr   Holds the pointer to the memory location which contains the partner's public value.
 *  \param[in]     partnerPublicValueLength Contains the length of the partner's public value in bytes.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \return        CRYPTO_E_SMALL_BUFFER   Request failed, the provided buffer is too small to store the result.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/
Std_ReturnType Crypto_KeyExchangeCalcSecret(uint32 cryptoKeyId,
                                            const uint8 *partnerPublicValuePtr,
                                            uint32 *partnerPublicValueLength)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}
/*Certificate Interface*/

/**********************************************************************************************************************
 *  Crypto_CertificateParse()
 *********************************************************************************************************************/
/*! \brief         Parses the certificate data stored in the key element CRYPTO_KE_CERT_DATA
 *                 and fills the key elements CRYPTO_KE_CERT_SIGNEDDATA, CRYPTO_KE_CERT_PARSEDPUBLICKEY and CRYPTO_KE_CERT_SIGNATURE.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be parsed.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType Crypto_CertificateParse(uint32 cryptoKeyId)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}

/**********************************************************************************************************************
 *  Crypto_CertificateVerify()
 *********************************************************************************************************************/
/*! \brief         Verifies the certificate stored in the key referenced by cryptoValidateKeyId with the certificate stored in the key referenced by cryptoKeyId.
 *  \param[in]     cryptoKeyId             Holds the identifier of the key which shall be used to validate the certificate.
 *  \param[in]     verifyCryptoKeyId       Holds the identifier of the key contain.
 *  \param[out]    verifyPtr               Holds a pointer to the memory location which will contain the result of the certificate verification.
 *  \return        E_OK                    Request successful.
 *  \return        E_NOT_OK                Request failed.
 *  \return        CRYPTO_E_BUSY           Request failed, Crypto Driver Object is busy.
 *  \reentrant     TRUE, but not for the same cryptoKeyId
 *  \synchronous   TRUE
 *********************************************************************************************************************/

Std_ReturnType Crypto_CertificateVerify(uint32 cryptoKeyId,
                                        uint32 verifyCryptoKeyId,
                                        Crypto_VerifyResultType *verifyPtr)
{
    Std_ReturnType ret = E_NOT_OK;
    return ret;

}
/*Main function*/

/**********************************************************************************************************************
 *  Crypto_MainFunction()
 *********************************************************************************************************************/
/*! \brief         If asynchronous job processing is configured and there are job queues, the function is called cyclically to process queued jobs.
 *********************************************************************************************************************/
void Crypto_MainFunction(void)
{
}
