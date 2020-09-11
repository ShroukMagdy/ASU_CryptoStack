#ifndef CRYPTO_CFG
#define CRYPTO_CFG
#include "Csm_Types.h"
#include "Platform_Types.h"

 

#define NO_DRIVERS 3
#define KEY_SIZE 1 
#define elementsNo 1
#define Random_Seed 16
//extern uint32 CDs_keys[NO_DRIVERS][NO_DRIVERS]; //i assume i only have 3 drivers 
//extern enum Crypto_AlgorithmFamilyType lop;



#define CRYPTO_DEV_ERROR_DETECT			    (STD_ON)


#define TotalKeyElementsDataSize 450
#define KeyElementsNumber 40
#define KeysNumber 10
/*
//uint8  ElementReadAccessEnum []={0x01,0x02,0x03,0x04};
//uint8  ElementWriteAccessEnum []={0x01,0x02,0x03,0x04};

typedef enum
{ 
	CRYPTO_RA_DENIED =0x01,
	CRYPTO_RA_INTERNAL_COPY=0x02,
	CRYPTO_RA_ALLOWED =0x03,
	CRYPTO_RA_ENCRYPTED =0x04
	
}
 ElementReadAccessEnum;

typedef enum
{
	CRYPTO_WA_DENIED =0x01,
	CRYPTO_WA_INTERNAL_COPY=0x02,
	CRYPTO_WA_ALLOWED =0x03,
	CRYPTO_WA_ENCRYPTED =0x04
}
ElementWriteAccessEnum ;

typedef struct
{
  //uint32 CryptoKeyElementId ;
	uint8 CryptoKeyElementReadAccess;
	uint8 CryptoKeyElementWriteAccess;
	uint32 CryptoKeyElementSize  ;
	boolean CryptoKeyElementAllowPartialAccess;
}CryptoKeyConfigInfo ;


typedef struct
{
	uint32 StartByte;
  uint32 EndByte;
	uint32 CryptoKeyElementId ;

} CryptoKeyElement;

typedef struct
{
	uint32 CryptoKeyID ;
	uint32 StartIndexOfElement ;
  uint32 EndIndexOfElement;

} CryptoKeys;






typedef struct {

CryptoKeyElement_MAC_KEYMATRIAL KeyMatrial;
CryptoKeyElement_MAC_KEYPROOF proof;
}MAC_KEY_TYPE;


typedef struct
{
	uint32 CryptoKeyElementId ;
	uint8 RS_Data[ Random_Seed];
	boolean CryptoKeyElementAllowPartialAccess;
	ElementReadAccessEnum CryptoKeyElementReadAccess;
	uint32 CryptoKeyElementSize  ;
	ElementWriteAccessEnum CryptoKeyElementWriteAccess;

} CryptoKeyElement_Random_CRYPTO_KE_RANDOM_SEED_STATE;

typedef struct
{
	uint32 CryptoKeyElementId ;
	uint8 KM_Data[ MAC_MKEY_SIZE];
	boolean CryptoKeyElementAllowPartialAccess;
	ElementReadAccessEnum CryptoKeyElementReadAccess;
	uint32 CryptoKeyElementSize  ;
	ElementWriteAccessEnum CryptoKeyElementWriteAccess;

} CryptoKeyElement_CRYPTO_KE_CIPHER_KEY;

typedef struct
{
	uint32 CryptoKeyElementId ;
	uint8 KM_Data[ MAC_MKEY_SIZE];
	boolean CryptoKeyElementAllowPartialAccess;
	ElementReadAccessEnum CryptoKeyElementReadAccess;
	uint32 CryptoKeyElementSize  ;
	ElementWriteAccessEnum CryptoKeyElementWriteAccess;

} CryptoKeyElement_CRYPTO_KE_CIPHER_IV;

typedef struct
{
	uint32 CryptoKeyElementId ;
	uint8 KM_Data[ MAC_MKEY_SIZE];
	boolean CryptoKeyElementAllowPartialAccess;
	ElementReadAccessEnum CryptoKeyElementReadAccess;
	uint32 CryptoKeyElementSize  ;
	ElementWriteAccessEnum CryptoKeyElementWriteAccess;

} CryptoKeyElement_CRYPTO_KE_CIPHER_PROOF;




// array of pointers to arrays 


typedef struct
{
	uint32 StartingKeyElementIDx;
	uint32 EndingKeyElementIDx;
	
}ElementIdRange;

typedef struct
{
uint32 CryptoKeyTypeId ;
ElementIdRange CryptoKeyElementRef ;
}CryptoKeyType;




typedef struct 
{
uint32 CryptoKeyId;
uint32 CryptoKeyTypeRef;

}CryptoKey;




typedef struct 
{
  Crypto_AlgorithmFamilyType F_family;               //The family of the algorithm 
	Crypto_AlgorithmModeType M_mode;
  Crypto_AlgorithmFamilyType S_secondaryFamily;      //The secondary family of the algorithm 
	 Crypto_ServiceInfoType  sj;	
}CryptoPrimitive;
*
typedef enum {
    
    CRYPTO_KE_RANDOM_SEED_STATE_ID,
    CRYPTO_KE_RANDOM_ALGORITHM_ID,
    
}key_element_Random_ID;




typedef struct
{
    uint32 KeyElementStartingIDx;
    uint32 KeyElementEndingIDx;
    uint32 CryptoKeyId;
    uint32 CryptoKeyDeriveIterations;
    boolean KeyValidity;
    boolean KeyAvaiableity;

} KeyType;
*/


typedef enum
{
    CRYPTO_RA_DENIED = 0x01,
    CRYPTO_RA_INTERNAL_COPY = 0x02,
    CRYPTO_RA_ALLOWED = 0x03,
    CRYPTO_RA_ENCRYPTED = 0x04

} ElementReadAccessEnum;

typedef enum
{
    CRYPTO_WA_DENIED = 0x01,
    CRYPTO_WA_INTERNAL_COPY = 0x02,
    CRYPTO_WA_ALLOWED = 0x03,
    CRYPTO_WA_ENCRYPTED = 0x04
} ElementWriteAccessEnum;

typedef enum
{
    CRYPTO_KE_FORMAT_BIN_CERT_CVC = 0x08,
    CRYPTO_KE_FORMAT_BIN_CERT_X509_V3 = 0x07,
    CRYPTO_KE_FORMAT_BIN_IDENT_PRIVATEKEY_PKCS8 = 0x03,
    CRYPTO_KE_FORMAT_BIN_IDENT_PUBLICKEY = 0x04,
    CRYPTO_KE_FORMAT_BIN_OCTET = 0x01,
    CRYPTO_KE_FORMAT_BIN_RSA_PRIVATEKEY = 0x05,
    CRYPTO_KE_FORMAT_BIN_RSA_PUBLICKEY = 0x06,
    CRYPTO_KE_FORMAT_BIN_SHEKEYS = 0x02,
} KeyElementFormat;
/*typedef struct
 {
 uint8 ElementData[CRYPTO_KE_MAC_KEY_SIZE];
 uint32 CryptoKeyElementSize;
 uint32 CryptoKeyElementId;
 uint8  CryptoKeyElementInitValue[CRYPTO_KE_MAC_KEY_SIZE];
 boolean CryptoKeyElementAllowPartialAccess;
 ElementReadAccessEnum CryptoKeyElementReadAccess;
 ElementWriteAccessEnum CryptoKeyElementWriteAccess;
 //uint8 *DataPtr;

 } CRYPTO_KE_MAC_KEY;
 */
typedef struct
{
    uint32 CryptoKeyElementSize;
    uint32 CryptoKeyElementId;
    ElementReadAccessEnum CryptoKeyElementReadAccess;
    ElementWriteAccessEnum CryptoKeyElementWriteAccess;
    KeyElementFormat CryptoKeyElementFormat;
    uint8 CryptoKeyElementInitValue;
    boolean CryptoKeyElementAllowPartialAccess;
} CryptoKeyElement;

typedef struct
{
    uint32 StartingByteIDx;
    uint32 EndingByteIDx;
    uint32 CryptoKeyElementId;

} KeyElementType;

typedef struct
{
    uint32 KeyElementStartingIDx;
    uint32 KeyElementEndingIDx;
    uint32 CryptoKeyId;
    uint32 CryptoKeyDeriveIterations;
    boolean KeyValidity;
    boolean KeyAvaiableity;

} KeyType;



#define CRYPTO_KE_MAC_KEY 1
#define CRYPTO_KE_MAC_PROOF 2 
#define CRYPTO_KE_SIGNATURE_KEY 1 
#define CRYPTO_KE_RANDOM_SEED_STATE 3 
#define CRYPTO_KE_RANDOM_ALGORITHM 4 
#define CRYPTO_KE_CIPHER_KEY_MATRIAL 1
#define CRYPTO_KE_CIPHER_IV 5 
#define CRYPTO_KE_CIPHER_PROOF 6 
#define CRYPTO_KE_CIPHER_2NDKEY 7 
#define CRYPTO_KE_KEYEXCHANGE_BASE 8 
#define CRYPTO_KE_KEYEXCHANGE_PRIVKEY 9  
#define CRYPTO_KE_CIPHER_KEY 1 
#define CRYPTO_KE_CIPHER_IV 5 
#define CRYPTO_KE_CIPHER_PROOF 6 
#define CRYPTO_KE_CIPHER_2NDKEY 7 
#define CRYPTO_KE_KEYEXCHANGE_BASE 8 
#define CRYPTO_KE_KEYEXCHANGE_PRIVKEY 9 
#define CRYPTO_KE_KEYEXCHANGE_OWNPUBKEY 10 
#define CYRPTO_KE_KEYEXCHANGE_SHAREDVALUE 1 
#define CRYPTO_KE_KEYEXCHANGE_ALGORITHM 12 
#define CRYPTO_KE_KEYDERIVATION_PASSWORD 1 
#define CRYPTO_KE_KEYDERIVATION_SALT 13 
#define CRYPTO_KE_KEYDERIVATION_ITERATIONS 14 
#define CRYPTO_KE_KEYDERIVATION_ALGORITHM 15 
#define CRYPTO_KE_KEYGENERATE_KEY 1 
#define CRYPTO_KE_KEYGENERATE_SEED 16 
#define CRYPTO_KE_KEYGENERATE_ALGORITHM 17 
#define CRYPTO_KE_CERTIFICATE_DATA 0 
#define CRYPTO_KE_CERTIFICATE_PARSING_FORMAT 18 
#define CRYPTO_KE_CERTIFICATE_CURRENT_TIME 19 
#define CRYPTO_KE_CERTIFICATE_VERSION 20 
#define CRYPTO_KE_CERTIFICATE_SERIALNUMBER 21 
#define CRYPTO_KE_CERTIFICATE_SIGNATURE_ALGORITHM 22 
#define CRYPTO_KE_CERTIFICATE_ISSUER 23 
#define CRYPTO_KE_CERTIFICATE_VALIDITY_NOT_BEFORE 24 
#define CRYPTO_KE_CERTIFICATE_VALIDITY_NOT_AFTER 25 
#define CRYPTO_KE_CERTIFICATE_SUBJECT 26 
#define CRYPTO_KE_CERTIFICATE_SUBJECT_PUBLIC_KEY 1 
#define CRYPTO_KE_CERTIFICATE_EXTENSIONS 27 
#define CRYPTO_KE_CERTIFICATE_SIGNATURE 28

 
 














#endif	
















