/*
 *  -------------------------------------------------------------------------------------------------------------------
 *  FILE DESCRIPTION
 *  -----------------------------------------------------------------------------------------------------------------*/
/*!        \file  Csm_Cfg.c
 *        \brief  MICROSAR Crypto Service Manager (CSM)
 *
 *      \details  Implementation of the MICROSAR Crypto Service Manager configuration (CSM)
 *
 *********************************************************************************************************************/
 
 /**********************************************************************************************************************
 *  INCLUDES
 *********************************************************************************************************************/
#include "Csm_Cfg.h"



 CsmHashConfig job_CsmHashConfig [6] ={ //array of structs
{CRYPTO_ALGOFAM_SHA1,20,CRYPTO_PROCESSING_SYNC,20}, //0
{CRYPTO_ALGOFAM_SHA2_224,8,CRYPTO_PROCESSING_SYNC,28},//1
{CRYPTO_ALGOFAM_SHA2_256,8,CRYPTO_PROCESSING_SYNC,32},//2
{CRYPTO_ALGOFAM_SHA2_384,8,CRYPTO_PROCESSING_SYNC,48},//3
{CRYPTO_ALGOFAM_SHA2_512,8,CRYPTO_PROCESSING_SYNC,64},//4
{CRYPTO_ALGOFAM_CUSTOM,8,CRYPTO_PROCESSING_SYNC,16}//5

};
CsmEncryptConfig job_CsmEncryptConfig[]={
{CRYPTO_ALGOFAM_3DES,0,24,CRYPTO_ALGOMODE_CBC,0,CRYPTO_ALGOFAM_NOT_SET,0,1000,CRYPTO_PROCESSING_SYNC,24},//6
{CRYPTO_ALGOFAM_AES,0,16,CRYPTO_ALGOMODE_CBC,0,CRYPTO_ALGOFAM_NOT_SET,0,1000,CRYPTO_PROCESSING_SYNC,10},//7
{CRYPTO_ALGOFAM_AES,0,24,CRYPTO_ALGOMODE_CBC,0,CRYPTO_ALGOFAM_NOT_SET,0,1000,CRYPTO_PROCESSING_SYNC,10},//8
{CRYPTO_ALGOFAM_AES,0,32,CRYPTO_ALGOMODE_CBC,0,CRYPTO_ALGOFAM_NOT_SET,0,1000,CRYPTO_PROCESSING_SYNC,10}//9
};
CsmDecryptConfig job_CsmDecryptConfig[]={
{CRYPTO_ALGOFAM_3DES,0,24,CRYPTO_ALGOMODE_CBC,0,CRYPTO_ALGOFAM_NOT_SET,0,1000,CRYPTO_PROCESSING_SYNC,24},//10
{CRYPTO_ALGOFAM_AES,0,32,CRYPTO_ALGOMODE_CBC,0,CRYPTO_ALGOFAM_NOT_SET,0,10000,CRYPTO_PROCESSING_SYNC,10}, //11
{CRYPTO_ALGOFAM_AES,0,16,CRYPTO_ALGOMODE_CBC,0,CRYPTO_ALGOFAM_NOT_SET,0,10000,CRYPTO_PROCESSING_SYNC,10}, //18
{CRYPTO_ALGOFAM_AES,0,24,CRYPTO_ALGOMODE_CBC,0,CRYPTO_ALGOFAM_NOT_SET,0,1000,CRYPTO_PROCESSING_SYNC,10},//20

};
CsmRandomGenerateConfig job_CsmRandomGenerateConfig[]={
    CRYPTO_ALGOFAM_RNG,0,CRYPTO_ALGOMODE_NOT_SET,0,CRYPTO_ALGOFAM_NOT_SET,0,CRYPTO_PROCESSING_SYNC,8
};
CsmMacGenerateConfig job_CsmMacGenerateConfig[]={
	{CRYPTO_ALGOFAM_SHA1,0,64,CRYPTO_ALGOMODE_HMAC,0,CRYPTO_ALGOFAM_NOT_SET,0,10,CRYPTO_PROCESSING_SYNC,10},
	{CRYPTO_ALGOFAM_SHA1,0,20,CRYPTO_ALGOMODE_HMAC,0,CRYPTO_ALGOFAM_NOT_SET,0,10,CRYPTO_PROCESSING_SYNC,10},
	{CRYPTO_ALGOFAM_SHA1,0,80,CRYPTO_ALGOMODE_HMAC,0,CRYPTO_ALGOFAM_NOT_SET,0,10,CRYPTO_PROCESSING_SYNC,10},
	{CRYPTO_ALGOFAM_AES,0,16,CRYPTO_ALGOMODE_CMAC,0,CRYPTO_ALGOFAM_NOT_SET,0,1000,CRYPTO_PROCESSING_SYNC,10}

};

CsmMacVerifyConfig job_CsmMacVerifyConfig []={
    {CRYPTO_ALGOFAM_SHA1,0,80,CRYPTO_ALGOMODE_HMAC,0,CRYPTO_ALGOFAM_NOT_SET,0,10,10,CRYPTO_PROCESSING_SYNC},//17
	{CRYPTO_ALGOFAM_AES,0,16,CRYPTO_ALGOMODE_CMAC,0,CRYPTO_ALGOFAM_NOT_SET,0,10,10,CRYPTO_PROCESSING_SYNC}//19
};

AllJobs jobs []={ // hashid encId decId hashPtr encPtr decPtr 
{0,0,0,0,0,0,&job_CsmHashConfig[0],NULL,NULL,NULL,NULL,NULL},//0
{1,0,0,0,0,0,&job_CsmHashConfig[1],NULL,NULL,NULL,NULL,NULL},//1
{2,0,0,0,0,0,&job_CsmHashConfig[2],NULL,NULL,NULL,NULL,NULL},//2
{3,0,0,0,0,0,&job_CsmHashConfig[3],NULL,NULL,NULL,NULL,NULL},//3
{4,0,0,0,0,0,&job_CsmHashConfig[4],NULL,NULL,NULL,NULL,NULL},//4
{5,0,0,0,0,0,&job_CsmHashConfig[5],NULL,NULL,NULL,NULL,NULL},//5
{0,0,0,0,0,0,NULL,&job_CsmEncryptConfig[0],NULL,NULL,NULL,NULL},//6
{0,1,0,0,0,0,NULL,&job_CsmEncryptConfig[1],NULL,NULL,NULL,NULL}, //7
{0,2,0,0,0,0,NULL,&job_CsmEncryptConfig[2],NULL,NULL,NULL,NULL},//8
{0,3,0,0,0,0,NULL,&job_CsmEncryptConfig[3],NULL,NULL,NULL,NULL}, //9
{0,0,0,0,0,0,NULL,NULL,&job_CsmDecryptConfig[0],NULL,NULL,NULL},//10
{0,0,1,0,0,0,NULL,NULL,&job_CsmDecryptConfig[1],NULL,NULL,NULL},//11
{0,0,0,0,0,0,NULL,NULL,NULL,&job_CsmRandomGenerateConfig[0],NULL,NULL},//12
{0,0,0,0,0,0,NULL,NULL,NULL,NULL,&job_CsmMacGenerateConfig[0],NULL},//13
{0,0,0,0,1,0,NULL,NULL,NULL,NULL,&job_CsmMacGenerateConfig[1],NULL},//14
{0,0,0,0,2,0,NULL,NULL,NULL,NULL,&job_CsmMacGenerateConfig[2],NULL},//15
{0,0,0,0,3,0,NULL,NULL,NULL,NULL,&job_CsmMacGenerateConfig[3],NULL},//16
{0,0,0,0,0,0,NULL,NULL,NULL,NULL,NULL,&job_CsmMacVerifyConfig [0]},//17
{0,0,2,0,0,0,NULL,NULL,&job_CsmDecryptConfig[2],NULL,NULL,NULL},//18
{0,0,0,0,0,1,NULL,NULL,NULL,NULL,NULL,&job_CsmMacVerifyConfig [1]},//19
{0,0,3,0,0,0,NULL,NULL,&job_CsmDecryptConfig[3],NULL,NULL,NULL}//20
};

Keys_ID Keys_ID_config[]={
    {cryifkey1},//0
    {cryifkey2},//1
    {cryifkey3},//2
    {cryifkey4},//3
    {cryifkey5},//4
    {cryifkey6},//5
    {cryifkey7},//6
    {cryifkey8},//7
    {cryifkey9},//8
    {cryifkey10}//9

};
CsmJob CsmJobs[]={ // 12 RNG
{0,FALSE,1,FALSE,0,0,&jobs[0],0},{1,FALSE,1,FALSE,0,0,&jobs[1],0} ,{2,FALSE,1,FALSE,0,0,&jobs[2],0}
,{3,FALSE,1,FALSE,0,0,&jobs[3],0},{4,FALSE,1,FALSE,0,0,&jobs[4],0},{5,FALSE,1,FALSE,0,0,&jobs[5],0},
{6,FALSE,1,FALSE,&Keys_ID_config[1],0,&jobs[6],0},{7,FALSE,1,FALSE,&Keys_ID_config[2],0,&jobs[7],0},
{8,FALSE,1,FALSE,&Keys_ID_config[3],0,&jobs[8],0},
{9,FALSE,1,FALSE,&Keys_ID_config[4],0,&jobs[9],0},{10,FALSE,1,FALSE,&Keys_ID_config[1],0,&jobs[10],0},
{11,FALSE,1,FALSE,&Keys_ID_config[4],0,&jobs[11],0},
{12,FALSE,1,FALSE,&Keys_ID_config[0],0,&jobs[12],0},{13,FALSE,1,FALSE,&Keys_ID_config[5],0,&jobs[13],0},
{14,FALSE,1,FALSE,&Keys_ID_config[6],0,&jobs[14],0},{15,FALSE,1,FALSE,&Keys_ID_config[7],0,&jobs[15],0},
{16,FALSE,1,FALSE,&Keys_ID_config[2],0,&jobs[16],0},{17,FALSE,1,FALSE,&Keys_ID_config[7],0,&jobs[17],0},
{18,FALSE,1,FALSE,&Keys_ID_config[2],0,&jobs[18],0},{19,FALSE,1,FALSE,&Keys_ID_config[2],0,&jobs[19],0},
{20,FALSE,1,FALSE,&Keys_ID_config[3],0,&jobs[20],0}
};
 



 
CsmKey CsmKey_config[]={
	{csmkey1,FALSE,cryifkey1},
	{csmkey2,FALSE,cryifkey2}
};



