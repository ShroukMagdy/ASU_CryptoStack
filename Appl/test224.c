#include "tests.h"

void testSH224(){



static Crypto_OperationModeType mode = CRYPTO_OPERATIONMODE_SINGLECALL;
static uint32 jobId =1;


uint8 dataArray[]="AshortstoryisapieceofprosefictionthattypicallycanbereadinonesittingandfocusesonaselfcontainedincidentorseriesoflinkedincidentswiththeintentofevokingasingleeffectormoodTheshortstoryisacraftedforminitsownright.ShortstoriesmakeuseofplotresonancesinotandthemmTheshortstoryisacraftedforminitsownright.Shortstoriesmakeuseofplot,resonance,andotherdynamiccomponentsasinanovel,buttypicallytoalesserdegree.Whiletheshortstoryislargelydistinctfromthenovelornovella/shortnovel,authorsgenerallydrawfromacommonpoolofliterarytechniques.Shortstorywritersmaydefinetheirworksaspartoftheartisticandpersonalexpressionofthefor";

static uint8 Hash[28]={0};

static uint32 a =28;
static uint32 *r =&a;

Std_ReturnType c =Csm_Hash(jobId,mode,dataArray ,sizeof(dataArray)-1,Hash,r);
		
//expected result 1a2c200ca5340f096e53dc81a59fdfdfaabb9a554b6f4038efc40366








};
