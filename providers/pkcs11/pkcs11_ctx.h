#ifndef PKSC11_CTX_H
#define PKSC11_CTX_H

#include <openssl/objects.h>
#include "../../include/crypto/rsa.h"

/* #define ENABLE_P11_EC */

#ifndef CK_PTR
# define CK_PTR *
#endif

#ifndef CK_BOOL
  typedef unsigned char CK_BOOL;
#endif                          /* CK_BOOL */

#ifndef CK_DECLARE_FUNCTION
# define CK_DECLARE_FUNCTION(returnType, name) \
         returnType name
#endif

#ifndef CK_DECLARE_FUNCTION_POINTER
# define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
         returnType (CK_PTR name)
#endif

#ifndef CK_CALLBACK_FUNCTION
# define CK_CALLBACK_FUNCTION(returnType, name) \
         returnType (CK_PTR name)
#endif

#ifndef NULL_PTR
# include <stddef.h> /* provides NULL */
# define NULL_PTR NULL
#endif

#ifndef PKCS11UNPACKED /* for PKCS11 modules that dont pack */
# pragma pack(push, 1)
#endif

#include "pkcs11-v30/pkcs11.h" /* official PKCS11 3.0 header */

#ifndef PKCS11UNPACKED
# pragma pack(pop)
#endif


#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include "internal/dso.h"
#include "internal/refcount.h"
#include "internal/thread_once.h"
#include "prov/provider_ctx.h"
#include <openssl/ec.h>
#define MAX_STORE_OBJ_COUNT 1000

typedef struct CK_OPENCRYPTOKI_FUNCTION_LIST {
    CK_VERSION version;
    CK_C_Initialize C_Initialize;
    CK_C_Finalize C_Finalize;
    CK_C_GetInfo C_GetInfo;
    CK_C_GetFunctionList C_GetFunctionList;
    CK_C_GetSlotList C_GetSlotList;
    CK_C_GetSlotInfo C_GetSlotInfo;
    CK_C_GetTokenInfo C_GetTokenInfo;
    CK_C_GetMechanismList C_GetMechanismList;
    CK_C_GetMechanismInfo C_GetMechanismInfo;
    CK_C_InitToken C_InitToken;
    CK_C_InitPIN C_InitPIN;
    CK_C_SetPIN C_SetPIN;
    CK_C_OpenSession C_OpenSession;
    CK_C_CloseSession C_CloseSession;
    CK_C_CloseAllSessions C_CloseAllSessions;
    CK_C_GetSessionInfo C_GetSessionInfo;
    CK_C_GetOperationState C_GetOperationState;
    CK_C_SetOperationState C_SetOperationState;
    CK_C_Login C_Login;
    CK_C_Logout C_Logout;
    CK_C_CreateObject C_CreateObject;
    CK_C_CopyObject C_CopyObject;
    CK_C_DestroyObject C_DestroyObject;
    CK_C_GetObjectSize C_GetObjectSize;
    CK_C_GetAttributeValue C_GetAttributeValue;
    CK_C_SetAttributeValue C_SetAttributeValue;
    CK_C_FindObjectsInit C_FindObjectsInit;
    CK_C_FindObjects C_FindObjects;
    CK_C_FindObjectsFinal C_FindObjectsFinal;
    CK_C_EncryptInit C_EncryptInit;
    CK_C_Encrypt C_Encrypt;
    CK_C_EncryptUpdate C_EncryptUpdate;
    CK_C_EncryptFinal C_EncryptFinal;
    CK_C_DecryptInit C_DecryptInit;
    CK_C_Decrypt C_Decrypt;
    CK_C_DecryptUpdate C_DecryptUpdate;
    CK_C_DecryptFinal C_DecryptFinal;
    CK_C_DigestInit C_DigestInit;
    CK_C_Digest C_Digest;
    CK_C_DigestUpdate C_DigestUpdate;
    CK_C_DigestKey C_DigestKey;
    CK_C_DigestFinal C_DigestFinal;
    CK_C_SignInit C_SignInit;
    CK_C_Sign C_Sign;
    CK_C_SignUpdate C_SignUpdate;
    CK_C_SignFinal C_SignFinal;
    CK_C_SignRecoverInit C_SignRecoverInit;
    CK_C_SignRecover C_SignRecover;
    CK_C_VerifyInit C_VerifyInit;
    CK_C_Verify C_Verify;
    CK_C_VerifyUpdate C_VerifyUpdate;
    CK_C_VerifyFinal C_VerifyFinal;
    CK_C_VerifyRecoverInit C_VerifyRecoverInit;
    CK_C_VerifyRecover C_VerifyRecover;
    CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
    CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
    CK_C_SignEncryptUpdate C_SignEncryptUpdate;
    CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
    CK_C_GenerateKey C_GenerateKey;
    CK_C_GenerateKeyPair C_GenerateKeyPair;
    CK_C_WrapKey C_WrapKey;
    CK_C_UnwrapKey C_UnwrapKey;
    CK_C_DeriveKey C_DeriveKey;
    CK_C_SeedRandom C_SeedRandom;
    CK_C_GenerateRandom C_GenerateRandom;
    CK_C_GetFunctionStatus C_GetFunctionStatus;
    CK_C_CancelFunction C_CancelFunction;
    CK_C_WaitForSlotEvent C_WaitForSlotEvent;
} CK_OPENCRYPTOKI_FUNCTION_LIST;

CK_OPENCRYPTOKI_FUNCTION_LIST *pkcs11_get_lib_functions();

typedef struct pkcs11_type_item_st {
    CK_MECHANISM_TYPE type;
    CK_MECHANISM_INFO info;
} PKCS11_TYPE_DATA_ITEM;

typedef struct pkcs11_type_st {
    OSSL_ALGORITHM  *algolist;
    OPENSSL_STACK   *items;
} PKCS11_TYPE_DATA;

typedef struct pkcs11_slot_st {
    CK_SLOT_ID       slotid;
    PKCS11_TYPE_DATA keymgmt;
    PKCS11_TYPE_DATA signature;
    PKCS11_TYPE_DATA asym_cipher;
    PKCS11_TYPE_DATA digest;
    PKCS11_TYPE_DATA store;
    CK_TOKEN_INFO    info;
} PKCS11_SLOT;

typedef struct pkcs11_st {
    PROV_CTX ctx;

    /* default core params */
    unsigned char *openssl_version;
    unsigned char *provider_name;
    unsigned char *userpin;
    unsigned char *sel_token;
    char *search_str;

    /* Slots are context base because the provider property can be different
     * and depends on the provider name.
     */
    OPENSSL_STACK *slots;
    CK_SLOT_ID sel_slot;
    int enable_digest;
    CK_SLOT_ID sel_slotidx_info;

    /* Error functions */
    OSSL_FUNC_core_new_error_fn             *core_new_error;
    OSSL_FUNC_core_set_error_debug_fn       *core_set_error_debug;
    OSSL_FUNC_core_vset_error_fn            *core_vset_error;

   /* functions offered by libcrypto to the providers */
}PKCS11_CTX;

typedef struct pkcs11_keymgmt_st {
    PKCS11_CTX *pkcs11_ctx;
    CK_MECHANISM_TYPE type;
    int selection;
    PKCS11_TYPE_DATA_ITEM *mechdata;
    char *label;
    char *id;
    int id_len;

    CK_SESSION_HANDLE session;
    void *import_data;
    union {
        struct pkcs11_rsa_st {
            CK_ULONG modulus_bits;
            BIGNUM *public_exponent;
        } rsa;
        struct pkcs11_ecdsa_st {
            CK_BYTE_PTR oid_name;
            int order;
            int oid_name_len;
        } ecdsa;
    }keyparam;
} PKCS11_KEYMGMT_CTX;

#define PKCS11_DEFAULT_ID_SIZE 20

typedef struct pkcs11_key_st {
    PKCS11_KEYMGMT_CTX *keymgmt_ctx;
    PKCS11_CTX *prov_ctx;
    CK_ULONG type;
    int is_private;
    CK_BYTE_PTR id;
    CK_ULONG id_len;

    struct pkcs11_rsa_data_st {
        BIGNUM *modulus;
        BIGNUM *pubexp;
        BIGNUM *privexp;
        BIGNUM *prime1;
        BIGNUM *prime2;
        BIGNUM *exp1;
        BIGNUM *exp2;
        BIGNUM *coef;
        RSA_PSS_PARAMS_30 *param_pss;
        int param_size;
        int param_bits;
        int param_sec_bits;
    }rsa;
    struct pkcs11_ecdsa_data_st {
        unsigned char *oid_name;
        int oid_name_len;
        int order;
        BIGNUM *pub_point;
        BIGNUM *priv_value;
    }ecdsa;
} PKCS11_KEY;

typedef struct pkcs11_sign_st {
    PKCS11_KEY *pkey;
    CK_MECHANISM_TYPE type;
    PKCS11_CTX *pkcs11_ctx;
    int nid_md;
    int nid_md_mgf1;
    int pss_salt_len;
    int isinit;
    CK_SESSION_HANDLE session;
} PKCS11_SIGN_CTX;

typedef struct pkcs11_digest_st {
    CK_MECHANISM_TYPE type;
    PKCS11_CTX *pkcs11_ctx;
    int nid;
    int digest_size;
    PKCS11_TYPE_DATA_ITEM *mechdata;
    CK_SESSION_HANDLE session;
    int is_init;
} PKCS11_DIGEST_CTX;

typedef struct pkcs11_cipher_st {
    CK_MECHANISM_TYPE type;
    PKCS11_CTX *pkcs11_ctx;
    unsigned int client_version;
    unsigned int alt_version;
    int nid;
    PKCS11_TYPE_DATA_ITEM *mechdata;
    int padmode;
    int isinit;
    int nid_md;
    int nid_md_mgf1;
    PKCS11_KEY *pkey;
    CK_SESSION_HANDLE session;
} PKCS11_CIPHER_CTX;
#define PKCS11_RSA_PKCS_PADDING      1
#define PKCS11_RSA_PKCS_OAEP_PADDING 2
#define PKCS11_RSA_PKCS_PSS_PADDING  3
#define PKCS11_RSA_PKCS1_WITH_TLS_PADDING 4

typedef struct pkcs11_store_obj_st {
    PKCS11_CTX *pkcs11_ctx;
    CK_OBJECT_HANDLE obj_handle;
    CK_OBJECT_CLASS obj_class;
    CK_KEY_TYPE obj_keytype;
    CK_SESSION_HANDLE session;
    int osl_class;
} PKCS11_STORE_OBJ;

#define PKCS11_SEARCH_NAME_SUBJECT          0x01
#define PKCS11_SEARCH_NAME_ISSUER           0x02
#define PKCS11_SEARCH_NAME_ALIAS            0x04
#define PKCS11_SEARCH_SERIAL                0x08
#define PKCS11_SEARCH_KEY_ALIAS             0x10
#define PKCS11_SEARCH_PRIV_KEY_WITH_CERT    0x20
#define PKCS11_SEARCH_PRIV_KEY_WITH_PUB_KEY 0x40

typedef struct pkcs11_store_search_st {
    X509_NAME *x509_subject;
    X509_NAME *x509_issuer;
    int search_flag;
    char *alias;
    BIGNUM *serial;
    char* key_alias;
    X509 *cert;
    EVP_PKEY *pubkey;
} PKCS11_STORE_SEARCH;

typedef struct pkcs11_store_st {
    PKCS11_CTX *pkcs11_ctx;
    int expected_type;
    PKCS11_STORE_SEARCH search_filter;
    CK_ULONG seek;
    CK_ULONG count;
    char loaded;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE obj_list[MAX_STORE_OBJ_COUNT];
    PKCS11_STORE_OBJ items[MAX_STORE_OBJ_COUNT];
} PKCS11_STORE_CTX;


int pkcs11_open_session(PKCS11_CTX *ctx, CK_SESSION_HANDLE_PTR session);
void pkcs11_close_session(PKCS11_CTX *ctx, CK_SESSION_HANDLE_PTR session);

#endif /* PKSC11_CTX_H */
