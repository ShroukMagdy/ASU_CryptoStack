#include "tests.h"

void testSH256(){



static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
static uint32 jobId =2;
uint8 dataArray[]="AshortstoryisapieceofprosefictionthattypicallycanbereadinonesittingandfocusesonaselfcontainedincidentorseriesoflinkedincidentswiththeintentofevokingasingleeffectormoodTheshortstoryisacraftedforminitsownright.ShortstoriesmakeuseofplotresonancesinotandthemmTheshortstoryisacraftedforminitsownright.Shortstoriesmakeuseofplot,resonance,andotherdynamiccomponentsasinanovel,buttypicallytoalesserdegree.Whiletheshortstoryislargelydistinctfromthenovelornovella/shortnovel,authorsgenerallydrawfromacommonpoolofliterarytechniques.Shortstorywritersmaydefinetheirworksaspartoftheartisticandpersonalexpressionofthefor";

static uint8 Hash[32]={0};

static uint32 a =32;
static uint32 *r =&a;
Std_ReturnType c =Csm_Hash(jobId,mode,dataArray ,sizeof(dataArray)-1,Hash,r);
	//expected result 32db77d027314c6d4ff288005b62a4d2b4f1f2a6046761d6f891a945bdcd93c6









};
