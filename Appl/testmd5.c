#include "tests.h"

void testMD5(){



static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
static uint32 jobId =5;



uint8 dataArray[]=

{0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x63,0x64,0x65,0x66,
0x67,0x68,0x69,0x6a,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x66,
0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
0x6f,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,
0x71,0x72,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x6e,0x6f,0x70,
0x71,0x72,0x73,0x74,0x75,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x63,0x64,0x65,0x66,
0x67,0x68,0x69,0x6a,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x66,
0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
0x6f,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,
0x71,0x72,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x6e,0x6f,0x70,
0x71,0x72,0x73,0x74,0x75,
0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x63,0x64,0x65,0x66,
0x67,0x68,0x69,0x6a,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x66,
0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
0x6f,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,
0x71,0x72,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x6e,0x6f,0x70,
0x71,0x72,0x73,0x74,0x75,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x63,0x64,0x65,0x66,
0x67,0x68,0x69,0x6a,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x66,
0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,
0x6f,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,
0x71,0x72,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x6e,0x6f,0x70,
0x71,0x72,0x73,0x74,0x75

};



//"AshortstoryisapieceofprosefictionthattypicallycanbereadinonesittingandfocusesonaselfcontainedincidentorseriesoflinkedincidentswiththeintentofevokingasingleeffectormoodTheshortstoryisacraftedforminitsownright.ShortstoriesmakeuseofplotresonancesinotandthemmTheshortstoryisacraftedforminitsownright.Shortstoriesmakeuseofplot,resonance,andotherdynamiccomponentsasinanovel,buttypicallytoalesserdegree.Whiletheshortstoryislargelydistinctfromthenovelornovella";


static uint8 Hash[16]={0};

static uint32 a =16;
static uint32 *r =&a;
Std_ReturnType c =Csm_Hash(jobId,mode,dataArray ,sizeof(dataArray),Hash,r);
		



//expected result 020dc7f2497c6f92e606c47b64fb1b33





};

