#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/stack.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/proverr.h>
#include <internal/provider.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include "pkcs11_kmgmt.h"
#include "pkcs11_ctx.h"
#include "pkcs11_utils.h"
#include "internal/param_build_set.h"


#define PKCS11_DEFAULT_RSA_MODULUS_BITS     2048
#define PKCS11_ECDSA_DEFAUL_NAME            "secp224r1"

CRYPTO_RWLOCK *pkcs11_kemgmt_lock = NULL;

void pkcs11_keygmgmt_create_lock() {
    if (pkcs11_kemgmt_lock == NULL)
        pkcs11_kemgmt_lock = CRYPTO_THREAD_lock_new();
}

void pkcs11_keygmgmt_free_lock() {
    if (pkcs11_kemgmt_lock != NULL) {
        CRYPTO_THREAD_lock_free(pkcs11_kemgmt_lock);
        pkcs11_kemgmt_lock = NULL;
    }
}

/* Internal id list that remembers which keys needs to be deleted when EVP_PKEY_free is called */
typedef struct TMP_GEN_KEY {
    unsigned char *id;
    int id_len;
    struct TMP_GEN_KEY *next;
    struct TMP_GEN_KEY *previous;
} TMP_GEN_KEY;
static TMP_GEN_KEY *tmp_gen_key = NULL;

TMP_GEN_KEY* pkcs11_keymgmt_find_tmp_gen_key(unsigned char* id, int id_len)
{
    TMP_GEN_KEY *ret = NULL;
    TMP_GEN_KEY *p = tmp_gen_key;
    while(p != NULL) {
        if (id_len == p->id_len) {
            if (memcmp(p->id, id, id_len) == 0) {
                ret = p;
                break;
            }
        }
        p = p->previous;
    };
    return ret;
}

void pkcs11_keymgmt_add_tmp_gen_key(unsigned char* id, int id_len)
{
    TMP_GEN_KEY *p = OPENSSL_zalloc(sizeof(TMP_GEN_KEY));
    p->id_len = id_len;
    p->id = OPENSSL_zalloc(p->id_len);
    memcpy(p->id, id, id_len);
    CRYPTO_THREAD_write_lock(pkcs11_kemgmt_lock);
    if (tmp_gen_key == NULL)
        tmp_gen_key = p;
    else {
        tmp_gen_key->next = p;
        p->previous = tmp_gen_key;
        tmp_gen_key = p;
    }
    CRYPTO_THREAD_unlock(pkcs11_kemgmt_lock);
}

int pkcs11_keymgmt_rm_tmp_gen_key(unsigned char* id, int id_len)
{
    TMP_GEN_KEY *p = NULL;
    int ret = 0;
    CRYPTO_THREAD_write_lock(pkcs11_kemgmt_lock);
    p = pkcs11_keymgmt_find_tmp_gen_key(id, id_len);
    if (p != NULL) {
        TMP_GEN_KEY *previous = p->previous;
        TMP_GEN_KEY *next = p->next;
        ret = 1;
        if (previous == NULL && next == NULL)
            tmp_gen_key = NULL;
        else if (previous == NULL)
            next->previous = NULL;
        else if (next == NULL) {
            previous->next = NULL;
            tmp_gen_key = previous;
        }
        else {
            previous->next = next;
            next->previous = previous;
        }
        OPENSSL_free(p->id);
        OPENSSL_free(p);
    }
    CRYPTO_THREAD_unlock(pkcs11_kemgmt_lock);
    return ret;
}

typedef struct TMP_GEN_ID {
    CK_BYTE_PTR *id;
    int id_len;
    struct TMP_GEN_ID *next;
    struct TMP_GEN_ID *previous;
} TMP_GEN_ID;
static TMP_GEN_ID *tmp_gen_id = NULL;

TMP_GEN_ID* pkcs11_keymgmt_find_tmp_gen_id(unsigned char* id, int id_len)
{
    TMP_GEN_ID *ret = NULL;
    TMP_GEN_ID *p = tmp_gen_id;
    while(p != NULL) {
        if (id_len == p->id_len) {
            if (memcmp(p->id, id, id_len) == 0) {
                ret = p;
                break;
            }
        }
        p = p->previous;
    };
    return ret;
}

void pkcs11_keymgmt_add_tmp_gen_id(unsigned char* id, int id_len)
{
    TMP_GEN_ID *p = OPENSSL_zalloc(sizeof(TMP_GEN_ID));
    p->id_len = id_len;
    p->id = OPENSSL_zalloc(p->id_len);
    memcpy(p->id, id, id_len);

    if (tmp_gen_id == NULL)
        tmp_gen_id = p;
    else {
        tmp_gen_id->next = p;
        p->previous = tmp_gen_id;
        tmp_gen_id = p;
    }
}

int pkcs11_keymgmt_rm_tmp_gen_id(unsigned char* id, int id_len)
{
    TMP_GEN_ID *p = NULL;
    int ret = 0;
    p = pkcs11_keymgmt_find_tmp_gen_id(id, id_len);
    if (p != NULL) {
        TMP_GEN_ID *previous = p->previous;
        TMP_GEN_ID *next = p->next;
        ret = 1;
        if (previous == NULL && next == NULL)
            tmp_gen_id = NULL;
        else if (previous == NULL)
            next->previous = NULL;
        else if (next == NULL) {
            previous->next = NULL;
            tmp_gen_id = previous;
        }
        else {
            previous->next = next;
            next->previous = previous;
        }
        OPENSSL_free(p->id);
        OPENSSL_free(p);
    }
    return ret;
}

/* Private functions */
PKCS11_TYPE_DATA_ITEM *pkcs11_keymgmt_get_mech_data(PKCS11_CTX *provctx, CK_MECHANISM_TYPE type,
                                            CK_ULONG bits);
static int pkcs11_set_ec_oid_name(CK_BYTE_PTR *pp, const char *name);
static int pkcs11_keymgmt_get_order_by_ec_oid(CK_BYTE_PTR pp, CK_ULONG len);
static void pkcs11_keymgmt_clear_keyparam(PKCS11_KEY *pkey);
static int pkcs11_keymgmt_is_key_equal(const PKCS11_KEY *pkey1, const PKCS11_KEY *pkey2, int ignorepriv);
extern uint16_t ossl_ifc_ffc_compute_security_bits(int n);
extern int ossl_rsa_pss_params_30_is_unrestricted(const RSA_PSS_PARAMS_30 *rsa_pss_params);

/* required functions */
static OSSL_FUNC_keymgmt_gen_fn                 pkcs11_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn         pkcs11_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_free_fn                pkcs11_keymgmt_free;
static OSSL_FUNC_keymgmt_has_fn                 pkcs11_keymgmt_has;
static OSSL_FUNC_keymgmt_match_fn               pkcs11_keymgmt_match;

/* additional functions */
static OSSL_FUNC_keymgmt_get_params_fn          pkcs11_keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn     pkcs11_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn pkcs11_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_set_params_fn      pkcs11_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_dup_fn                 pkcs11_keymgmt_dup;

/* create / free key from store object */
static OSSL_FUNC_keymgmt_load_fn                pkcs11_keymgmt_load;
static OSSL_FUNC_keymgmt_new_fn                 pkcs11_keymgmt_newdata;

#define PKCS11_KEYMGMT_rsa_algo_descr        "PKSC11 keymgmt rsa algo"
#define PKCS11_KEYMGMT_ec_algo_descr         "PKSC11 keymgmt ec algo"
#define PKCS11_KEYMGMT_GEN_INIT_FCT(name)    pkcs11_##name##_keymgmt_gen_init
#define PKCS11_KEYMGMT_IMPORT_FCT(name)      pkcs11_##name##_keymgmt_import
#define PKCS11_KEYMGMT_IMPORT_TYPES_FCT(name)  pkcs11_##name##_keymgmt_import_types
#define PKCS11_KEYMGMT_EXPORT_FCT(name)      pkcs11_##name##_keymgmt_export
#define PKCS11_KEYMGMT_EXPORT_TYPES_FCT(name)  pkcs11_##name##_keymgmt_export_types
#define PKCS11_KEYMGMT_DB_TBL(name)          pkcs11_keymgmt_##name##_dp_tbl
#define PKCS11_KEYMGMT_ALGO_DESCR(name)      pkcs11_keymgmt_##name##_algo_description

#define PKCS11_PROV_FUNC_KEYMGMT(name)                    \
static OSSL_FUNC_keymgmt_gen_init_fn        PKCS11_KEYMGMT_GEN_INIT_FCT(name); \
static OSSL_FUNC_keymgmt_import_fn          PKCS11_KEYMGMT_IMPORT_FCT(name); \
static OSSL_FUNC_keymgmt_import_types_fn    PKCS11_KEYMGMT_IMPORT_TYPES_FCT(name); \
static OSSL_FUNC_keymgmt_export_fn          PKCS11_KEYMGMT_EXPORT_FCT(name); \
static OSSL_FUNC_keymgmt_export_types_fn    PKCS11_KEYMGMT_EXPORT_TYPES_FCT(name); \
/* Define Algorith description */                               \
static char* PKCS11_KEYMGMT_ALGO_DESCR(name) = PKCS11_KEYMGMT_##name##_algo_descr; \
/* Define the dispatch table for the specific digest */         \
const OSSL_DISPATCH PKCS11_KEYMGMT_DB_TBL(name)[] = {           \
    {OSSL_FUNC_KEYMGMT_GEN_INIT,                                \
            (void (*)(void))PKCS11_KEYMGMT_GEN_INIT_FCT(name)}, \
    {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                          \
            (void (*)(void))pkcs11_keymgmt_gen_set_params},     \
    {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                     \
            (void (*)(void))pkcs11_keymgmt_gen_settable_params},\
    {OSSL_FUNC_KEYMGMT_GEN,                                     \
            (void (*)(void))pkcs11_keymgmt_gen},                \
    {OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                             \
            (void (*)(void))pkcs11_keymgmt_gen_cleanup},        \
    {OSSL_FUNC_KEYMGMT_FREE,                                    \
            (void (*)(void))pkcs11_keymgmt_free},               \
    {OSSL_FUNC_KEYMGMT_GET_PARAMS,                              \
            (void (*)(void))pkcs11_keymgmt_get_params},         \
    {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                         \
            (void (*)(void))pkcs11_keymgmt_gettable_params},    \
    {OSSL_FUNC_KEYMGMT_HAS,                                     \
            (void (*)(void))pkcs11_keymgmt_has},                \
    {OSSL_FUNC_KEYMGMT_MATCH,                                   \
            (void (*)(void))pkcs11_keymgmt_match },             \
    /* For loading and freeing key from store reference */      \
    {OSSL_FUNC_KEYMGMT_LOAD,                                    \
            (void (*)(void))pkcs11_keymgmt_load},               \
    {OSSL_FUNC_KEYMGMT_IMPORT,                                  \
            (void (*)(void))PKCS11_KEYMGMT_IMPORT_FCT(name)},   \
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                            \
            (void (*)(void))PKCS11_KEYMGMT_IMPORT_TYPES_FCT(name)}, \
    {OSSL_FUNC_KEYMGMT_EXPORT,                                  \
            (void (*)(void))PKCS11_KEYMGMT_EXPORT_FCT(name)},   \
    {OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                            \
            (void (*)(void))PKCS11_KEYMGMT_EXPORT_TYPES_FCT(name)}, \
    {OSSL_FUNC_KEYMGMT_NEW,                                     \
            (void (*)(void))pkcs11_keymgmt_newdata},            \
    {OSSL_FUNC_KEYMGMT_DUP,                                     \
            (void (*)(void))pkcs11_keymgmt_dup},                \
    {0, NULL}                                                   \
};                                                              \

PKCS11_PROV_FUNC_KEYMGMT(rsa)
PKCS11_PROV_FUNC_KEYMGMT(ec)

const OSSL_PARAM pkcs11_keymgmt_gettable_params_tbl[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_END
};

const OSSL_PARAM pkcs11_keymgmt_gen_settable_params_tbl[] = {
    /* RSA */
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    /* ECDSA */
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_ALIAS, NULL, 0),
    OSSL_PARAM_END
};

static void *pkcs11_rsa_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void)params;
    PKCS11_KEYMGMT_CTX *genctx = NULL;
    PKCS11_KEYMGMT_CTX *ret = NULL;
    PKCS11_CTX *ctx = (PKCS11_CTX*)provctx;

    if (ctx == NULL)
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 &&
        (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0 &&
        (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        goto end;

    genctx = OPENSSL_zalloc(sizeof(*genctx));
    if (genctx == NULL)
        goto end;

    genctx->selection = selection;
    genctx->type = CKM_RSA_PKCS_KEY_PAIR_GEN;
    genctx->keyparam.rsa.public_exponent = BN_new();
    if (genctx->keyparam.rsa.public_exponent == NULL)
        goto end;

    if (!BN_set_word(genctx->keyparam.rsa.public_exponent, RSA_F4))
        goto end;

    genctx->keyparam.rsa.modulus_bits = PKCS11_DEFAULT_RSA_MODULUS_BITS;
    genctx->mechdata = pkcs11_keymgmt_get_mech_data(ctx, genctx->type, PKCS11_DEFAULT_RSA_MODULUS_BITS);
    if (!genctx->mechdata)
        goto end;

    genctx->pkcs11_ctx = ctx;

    pkcs11_close_session(ctx, &genctx->session);
    if (pkcs11_open_session(ctx, &genctx->session) == 0)
        goto end;

    ret = genctx;

end:
    if (ret == NULL) {
        if (genctx != NULL) {
            if (ctx)
                pkcs11_close_session(ctx, &genctx->session);
            BN_free(genctx->keyparam.rsa.public_exponent);
            OPENSSL_free(genctx);
        }
    }
    return ret;
}

static const OSSL_PARAM rsa_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0),
    OSSL_PARAM_END
};

static void *pkcs11_keymgmt_newdata(void *provctx)
{
    PKCS11_KEY *pkey = NULL;
    PKCS11_CTX *ctx = (PKCS11_CTX*)provctx;

    if (!ossl_prov_is_running())
        return NULL;

    pkey = OPENSSL_zalloc(sizeof(PKCS11_KEY));
    pkey->prov_ctx = ctx;

    return pkey;
}

void* pkcs11_keymgmt_dup(const void *keydata_from, int selection)
{
    PKCS11_KEY *from_key = (PKCS11_KEY*)keydata_from;
    PKCS11_KEY *to_key = NULL;
    PKCS11_CTX *ctx = from_key->prov_ctx;
    to_key = pkcs11_keymgmt_newdata(ctx);
    if (to_key == NULL)
        goto end;

    to_key->type = from_key->type;
    to_key->is_private = from_key->is_private;
    to_key->id_len = from_key->id_len;
    if (from_key->id_len > 0) {
        to_key->id = OPENSSL_zalloc(from_key->id_len);
        memcpy(to_key->id, from_key->id, from_key->id_len);
    }

    switch(from_key->type) {
    case CKK_RSA:
        to_key->rsa.modulus = BN_dup(from_key->rsa.modulus);
        to_key->rsa.pubexp = BN_dup(from_key->rsa.pubexp);
        to_key->rsa.privexp = BN_dup(from_key->rsa.privexp);
        to_key->rsa.prime1 = BN_dup(from_key->rsa.prime1);
        to_key->rsa.prime2 = BN_dup(from_key->rsa.prime2);
        to_key->rsa.exp1 = BN_dup(from_key->rsa.exp1);
        to_key->rsa.exp2 = BN_dup(from_key->rsa.exp2);
        to_key->rsa.coef = BN_dup(from_key->rsa.coef);
        if (from_key->rsa.param_pss != NULL) {
            to_key->rsa.param_pss = OPENSSL_zalloc(sizeof(RSA_PSS_PARAMS_30));
            ossl_rsa_pss_params_30_copy(to_key->rsa.param_pss, from_key->rsa.param_pss);
        }
        to_key->rsa.param_size = from_key->rsa.param_size;
        to_key->rsa.param_bits = from_key->rsa.param_bits;
        to_key->rsa.param_sec_bits = from_key->rsa.param_sec_bits;
        break;
    case CKK_ECDSA:
        to_key->ecdsa.oid_name_len = from_key->ecdsa.oid_name_len;
        if (from_key->ecdsa.oid_name_len > 0) {
            to_key->ecdsa.oid_name = OPENSSL_zalloc(from_key->ecdsa.oid_name_len);
            memcpy(to_key->ecdsa.oid_name, from_key->ecdsa.oid_name, from_key->ecdsa.oid_name_len);
        }
        to_key->ecdsa.order = from_key->ecdsa.order;
        to_key->ecdsa.pub_point = BN_dup(from_key->ecdsa.pub_point);
        if (from_key->ecdsa.priv_value)
            to_key->ecdsa.priv_value = BN_dup(from_key->ecdsa.priv_value);
        break;
    }

end:
    return to_key;
}

static const OSSL_PARAM *pkcs11_rsa_keymgmt_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return rsa_key_types;
    return NULL;
}

static const OSSL_PARAM *pkcs11_rsa_keymgmt_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return rsa_key_types;
    return NULL;
}

static int pkcs11_rsa_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_n = NULL, *param_e = NULL, *param_d = NULL;
    const OSSL_PARAM *param_bits = NULL, *param_sec_bits = NULL, *param_size = NULL;
    const OSSL_PARAM *param_f1 = NULL, *param_f2 = NULL, *param_ex1 = NULL,
                     *param_ex2 = NULL, *param_co = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *f1 = NULL,
           *f2 = NULL, *ex1 = NULL, *ex2 = NULL, *co = NULL;
    PKCS11_KEY *pkey = (PKCS11_KEY*)keydata;
    PKCS11_CTX *ctx = (PKCS11_CTX*)pkey->prov_ctx;
    int pss_defaults_set = 0;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    int param_ival = 0;
    int ret = 0;

    if (pkey == NULL)
        goto end;

    if ((selection &
        (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) == 0)
        goto end;

    pkey->type = CKK_RSA;
    pkey->rsa.modulus = BN_new();
    pkey->rsa.pubexp = BN_new();
    pkey->rsa.param_pss = OPENSSL_zalloc(sizeof(RSA_PSS_PARAMS_30));
    ret = ossl_rsa_pss_params_30_fromdata(pkey->rsa.param_pss, &pss_defaults_set, params, ctx->ctx.libctx);

    param_n = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
    param_e = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
    param_d = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);

    if ((param_n != NULL && !OSSL_PARAM_get_BN(param_n, &n))
        || (param_e != NULL && !OSSL_PARAM_get_BN(param_e, &e))
        || (param_d != NULL && !OSSL_PARAM_get_BN(param_d, &d)))
        goto end;

    BN_copy(pkey->rsa.modulus, n);
    BN_copy(pkey->rsa.pubexp, e);
    pkey->is_private = (d != NULL ? 1 : 0);
    if (pkey->is_private) {
        param_f1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR1);
        param_f2 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
        param_ex1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT1);
        param_ex2 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT2);
        param_co = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT1);
        pkey->rsa.privexp = BN_new();
        BN_copy(pkey->rsa.privexp, d);
        if (param_f1 != NULL && OSSL_PARAM_get_BN(param_f1, &f1)) {
            pkey->rsa.prime1 = BN_new();
            BN_copy(pkey->rsa.prime1, f1);
        }
        if (param_f2 != NULL && OSSL_PARAM_get_BN(param_f2, &f2)) {
            pkey->rsa.prime2 = BN_new();
            BN_copy(pkey->rsa.prime2, f2);
        }
        if (param_ex1 != NULL && OSSL_PARAM_get_BN(param_ex1, &ex1)) {
            pkey->rsa.exp1 = BN_new();
            BN_copy(pkey->rsa.exp1, ex1);
        }
        if (param_ex2 != NULL && OSSL_PARAM_get_BN(param_ex2, &ex2)) {
            pkey->rsa.exp2 = BN_new();
            BN_copy(pkey->rsa.exp2, ex2);
        }
        if (param_co != NULL && OSSL_PARAM_get_BN(param_co, &co)) {
            pkey->rsa.coef = BN_new();
            BN_copy(pkey->rsa.coef, co);
        }
    }

    param_bits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_BITS);
    param_sec_bits = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    param_size = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (param_bits != NULL && !OSSL_PARAM_get_int(param_bits, &param_ival))
        pkey->rsa.param_bits = param_ival;
    if (param_sec_bits != NULL && !OSSL_PARAM_get_int(param_sec_bits, &param_ival))
        pkey->rsa.param_sec_bits = param_ival;
    if (param_size != NULL && !OSSL_PARAM_get_int(param_size, &param_ival))
        pkey->rsa.param_size = param_ival;

    ret = pkcs11_open_session(ctx, &session);
    if (ret != 1)
        goto end;

    obj = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx, pkey, &session);
    if (obj == CK_INVALID_HANDLE) {
        /* It seems key is not available in the store.
         * This can happening with certificate chain where one cert public key is to be used for verifying the other
         * or the store add api is called with a key to be added to the store.
         * In this case we have to create a new public key.
         */
        PKCS11_KEYMGMT_CTX *genctx2 = NULL;
        int gen_selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        if (pkey->is_private)
            gen_selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
        genctx2 = (PKCS11_KEYMGMT_CTX *)pkcs11_rsa_keymgmt_gen_init(ctx, gen_selection, NULL);
        if (genctx2 == NULL)
            goto end;
        genctx2->import_data = pkey;
        pkcs11_keymgmt_gen(genctx2, NULL, NULL);
        OPENSSL_free(genctx2);
    }

    obj = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx, pkey, &session);
    if (obj == CK_INVALID_HANDLE)
        goto end;

    ret = 1;
end:
    pkcs11_close_session(ctx, &session);
    if (n)
        BN_free(n);
    if (e)
        BN_free(e);
    if (d)
        BN_free(d);
    if (f1)
        BN_free(f1);
    if (f2)
        BN_free(f2);
    if (ex1)
        BN_free(ex1);
    if (ex2)
        BN_free(ex2);
    if (co)
        BN_free(co);
    return ret;
}

static int pkcs11_rsa_keymgmt_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_callback, void *cbarg)
{
    PKCS11_KEY *key = (PKCS11_KEY *)keydata;
    const RSA_PSS_PARAMS_30 *pss_params = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;
    int ok = 1;
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;

    if (key->rsa.modulus == NULL) {
        ret = pkcs11_open_session(key->prov_ctx, &session);
        obj = pkcs11_keymgmt_get_keyhandle_from_keyparam(key->prov_ctx,
                                                   key, &session);
        if (obj == CK_INVALID_HANDLE)
            goto end;
        if (pkcs11_keymgmt_get_keyparam_from_key(key->prov_ctx,
                                             key, obj, session,
                                             0) == 0)
            goto end;
    }
    pss_params = key->rsa.param_pss;

    /* Only public key and pss can be extracted. */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0 &&
        (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) == 0)
        goto end;

    param_bld = OSSL_PARAM_BLD_new();
    if (param_bld == NULL)
        goto end;

    if (selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
        ok = ok && (ossl_rsa_pss_params_30_is_unrestricted(pss_params) ||
                    ossl_rsa_pss_params_30_todata(pss_params, param_bld, NULL));
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        n = key->rsa.modulus;
        e = key->rsa.pubexp;
        ok = ok && (ossl_param_build_set_bn(param_bld, params, OSSL_PKEY_PARAM_RSA_N, n) &&
                    ossl_param_build_set_bn(param_bld, params, OSSL_PKEY_PARAM_RSA_E, e));
    }
    if (!ok || (params = OSSL_PARAM_BLD_to_param(param_bld)) == NULL)
        goto end;
    ret = param_callback(params, cbarg);
end:
    if (key && session != CK_INVALID_HANDLE)
        pkcs11_close_session(key->prov_ctx, &session);
    if (params)
        OSSL_PARAM_free(params);
    if (param_bld)
        OSSL_PARAM_BLD_free(param_bld);
    return ret;
}

static void *pkcs11_ec_keymgmt_gen_init(void *provctx, int selection, const OSSL_PARAM params[])
{
    (void)params;
    PKCS11_KEYMGMT_CTX *genctx = NULL;
    PKCS11_KEYMGMT_CTX *ret = NULL;
    PKCS11_CTX *ctx = (PKCS11_CTX*)provctx;

    if (ctx == NULL)
        goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0 &&
        (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0 &&
        (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) == 0)
        goto end;

    genctx = OPENSSL_zalloc(sizeof(*genctx));
    if (genctx == NULL)
        goto end;

    genctx->selection = selection;
    genctx->type = CKM_ECDSA_KEY_PAIR_GEN;
    genctx->keyparam.ecdsa.oid_name_len = pkcs11_set_ec_oid_name(&genctx->keyparam.ecdsa.oid_name,
                                                                 PKCS11_ECDSA_DEFAUL_NAME);
    if (genctx->keyparam.ecdsa.oid_name == NULL)
        goto end;

    genctx->keyparam.ecdsa.order = pkcs11_keymgmt_get_order_by_ec_oid(genctx->keyparam.ecdsa.oid_name,
                                                                      genctx->keyparam.ecdsa.oid_name_len);
    genctx->mechdata = pkcs11_keymgmt_get_mech_data(ctx, genctx->type, 0);
    if (!genctx->mechdata)
        goto end;

    genctx->pkcs11_ctx = ctx;

    pkcs11_close_session(ctx, &genctx->session);
    if (pkcs11_open_session(ctx, &genctx->session) == 0)
        goto end;

    ret = genctx;

end:
    if (ret == NULL) {
        if (genctx != NULL) {
            if (ctx)
                pkcs11_close_session(ctx, &genctx->session);
            OPENSSL_free(genctx->keyparam.ecdsa.oid_name);
            OPENSSL_free(genctx);
        }
    }
    return ret;
}

static const OSSL_PARAM ec_key_types[] = {
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *pkcs11_ec_keymgmt_import_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ec_key_types;
    return NULL;
}

static const OSSL_PARAM *pkcs11_ec_keymgmt_export_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return ec_key_types;
    return NULL;
}

static int pkcs11_ec_keymgmt_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    int ret = 0;
#ifdef ENABLE_P11_EC
    const OSSL_PARAM *pgroup, *pec_point, *ppriv_value = NULL;
    PKCS11_KEY *pkey = (PKCS11_KEY*)keydata;
    PKCS11_CTX *ctx = (PKCS11_CTX*)pkey->prov_ctx;
    CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    char *ec_group = NULL;
    char *ec_point_val = NULL;
    char *ec_point_bitstream_val = NULL;
    char *p = NULL;
    BIGNUM *bn_priv_val = NULL;
    size_t length = 0;

    if (pkey == NULL)
        goto end;

    if ((selection &
        (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) == 0)
        goto end;

    pgroup = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    pec_point = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    ppriv_value = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (!pgroup && !pec_point)
        goto end;

    if (!OSSL_PARAM_get_utf8_string(pgroup, &ec_group, length))
        goto end;

    pkey->type = CKK_ECDSA;

    if (pkey->ecdsa.oid_name != NULL)
        OPENSSL_free(pkey->ecdsa.oid_name);
    pkey->ecdsa.oid_name_len = pkcs11_set_ec_oid_name(&pkey->ecdsa.oid_name,
                                                      ec_group);
    if (pkey->ecdsa.oid_name == NULL)
        goto end;

    pkey->ecdsa.order = pkcs11_keymgmt_get_order_by_ec_oid(pkey->ecdsa.oid_name,
                                                           pkey->ecdsa.oid_name_len);

    length = 0;
    if (!OSSL_PARAM_get_octet_string(pec_point, (void**)&ec_point_val, length, &length))
        goto end;

    ec_point_bitstream_val = OPENSSL_zalloc(length + 2);
    p = ec_point_bitstream_val;
    (*p) = 0x04;
    p++;
    (*p) = length;
    p++;
    memcpy(p, ec_point_val, length);

    if (pkey->ecdsa.pub_point) {
        BN_clear_free(pkey->ecdsa.pub_point);
        pkey->ecdsa.pub_point = NULL;
    }

    pkey->ecdsa.pub_point = BN_bin2bn((const unsigned char*)ec_point_bitstream_val, length + 2, pkey->ecdsa.pub_point);
    if (pkey->ecdsa.pub_point == NULL)
        goto end;

    pkey->is_private = (ppriv_value != NULL ? 1 : 0);

    if (pkey->ecdsa.priv_value) {
        BN_clear_free(pkey->ecdsa.priv_value);
        pkey->ecdsa.priv_value = NULL;
    }

    if (ppriv_value != NULL) {
        OSSL_PARAM_get_BN(ppriv_value, &bn_priv_val);
        pkey->ecdsa.priv_value = BN_new();
        BN_copy(pkey->ecdsa.priv_value, bn_priv_val);
    }

    ret = pkcs11_open_session(ctx, &session);
    if (ret != 1)
        goto end;

    ret = 0;
    obj = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx, pkey, &session);
    if (obj == CK_INVALID_HANDLE) {
        PKCS11_KEYMGMT_CTX *genctx2 = NULL;
        int gen_selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        if (pkey->is_private)
            gen_selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
        genctx2 = (PKCS11_KEYMGMT_CTX *)pkcs11_ec_keymgmt_gen_init(ctx, gen_selection, NULL);
        if (genctx2 == NULL)
            goto end;
        genctx2->import_data = pkey;
        pkcs11_keymgmt_gen(genctx2, NULL, NULL);
        OPENSSL_free(genctx2);
    }

    obj = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx, pkey, &session);
    if (obj == CK_INVALID_HANDLE)
        goto end;

    ret = 1;
end:
    pkcs11_close_session(ctx, &session);
    if (ret == 0) {
        if (pkey->ecdsa.oid_name != NULL)
            OPENSSL_free(pkey->ecdsa.oid_name);
        pkey->ecdsa.oid_name = NULL;
        if (pkey->ecdsa.pub_point)
            BN_clear_free(pkey->ecdsa.pub_point);
        pkey->ecdsa.pub_point = NULL;
    }
    if (ec_group)
        OPENSSL_free(ec_group);
    if (ec_point_val)
        OPENSSL_free(ec_point_val);
    if (bn_priv_val)
        BN_free(bn_priv_val);
#endif
    return ret;
}

static int pkcs11_ec_keymgmt_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_callback, void *cbarg)
{
    return 0;
}

PKCS11_TYPE_DATA_ITEM *pkcs11_keymgmt_get_mech_data(PKCS11_CTX *provctx, CK_MECHANISM_TYPE type,
                                            CK_ULONG bits)
{
    int i = 0;
    PKCS11_SLOT *slot = NULL;
    PKCS11_TYPE_DATA_ITEM *pkeymgmt = NULL;

    slot = pkcs11_get_slot(provctx);
    if (slot) {
        for (i = 0; i < OPENSSL_sk_num(slot->keymgmt.items); i++) {
            pkeymgmt = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(slot->keymgmt.items, i);
            if (pkeymgmt->type == type) {
                if (bits > 0) {
                    if (bits >= pkeymgmt->info.ulMinKeySize
                        && bits <= pkeymgmt->info.ulMaxKeySize)
                        return pkeymgmt;
                    continue;
                }
                return pkeymgmt;
            }
        }
    }
    return NULL;
}

static int pkcs11_keymgmt_create_id(PKCS11_CTX *ctx, CK_SESSION_HANDLE session, CK_BYTE_PTR buf, CK_ULONG buflen)
{
    CK_ATTRIBUTE attr_id = {CKA_ID, NULL, 0};
    CK_RV rv = CKR_OK;
    int ret = 0;
    CK_ULONG count = 0;
    CK_OBJECT_HANDLE obj = 0;

    CRYPTO_THREAD_write_lock(pkcs11_kemgmt_lock);
    for(; ret == 0;) {
        rv = pkcs11_get_lib_functions()->C_GenerateRandom(session, buf, buflen);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx, rv);
            goto end;
        }
        attr_id.pValue = buf;
        attr_id.ulValueLen = buflen;
        rv = pkcs11_get_lib_functions()->C_FindObjectsInit(
                    session, &attr_id, 1);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx, rv);
            goto end;
        }
        rv = pkcs11_get_lib_functions()->C_FindObjects(session,
                                                       &obj, 1,
                                                       &count);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx, rv);
            goto end;
        }

        rv = pkcs11_get_lib_functions()->C_FindObjectsFinal(session);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx, rv);
            goto end;
        }
        if (count <= 0 && pkcs11_keymgmt_find_tmp_gen_id(buf, buflen) == NULL)
            break;
    }
    pkcs11_keymgmt_add_tmp_gen_id(buf, buflen);
    CRYPTO_THREAD_unlock(pkcs11_kemgmt_lock);
    ret = 1;
end:
    return ret;
}

#define BN_P11_2_BIN(len, buf, bn) \
    len = BN_num_bytes(bn); \
    buf = OPENSSL_zalloc(len); \
    len = BN_bn2bin(bn, buf);

CK_OBJECT_HANDLE pkcs11_rsa_keymgmt_gen_from_import(PKCS11_KEYMGMT_CTX *gctx,
                                                    PKCS11_KEY *ikey, int selection)
{
    CK_OBJECT_HANDLE ret = CK_INVALID_HANDLE;
    CK_BBOOL is_true = CK_TRUE;
    CK_BBOOL is_false = CK_FALSE;
    CK_ULONG pub_key_class = CKO_PUBLIC_KEY;
    CK_ULONG priv_key_class = CKO_PRIVATE_KEY;
    CK_ULONG keytype = CKK_RSA;
    unsigned char *bufs[] = {0,0,0,0,0,0,0,0,0,0,0,0};
    size_t len = 0;
    int idx = 0;
    CK_ATTRIBUTE *tbl = NULL;
    size_t tbl_len = 0;
    OPENSSL_STACK *stack = NULL;
    CK_ATTRIBUTE_PTR pattr = NULL;
    CK_RV rv = CKR_CANCEL;
    size_t i = 0;
    CK_BYTE id[PKCS11_DEFAULT_ID_SIZE];

    stack = OPENSSL_sk_new_null();
    if (gctx->id != NULL && gctx->id_len >0) {
        ikey->id_len = gctx->id_len;
        ikey->id = OPENSSL_zalloc(ikey->id_len);
        memcpy(ikey->id, gctx->id, ikey->id_len);
        pkcs11_add_attribute(stack, CKA_ID, ikey->id, ikey->id_len);
    } else {
        if (pkcs11_keymgmt_create_id(gctx->pkcs11_ctx, gctx->session, id, sizeof(id)) == 0)
            goto end;
        ikey->id_len = PKCS11_DEFAULT_ID_SIZE;
        ikey->id = OPENSSL_zalloc(PKCS11_DEFAULT_ID_SIZE);
        memcpy(ikey->id, id, PKCS11_DEFAULT_ID_SIZE);
        pkcs11_add_attribute(stack, CKA_ID, ikey->id, PKCS11_DEFAULT_ID_SIZE);
    }
    if (gctx->label != NULL) {
        int label_len = strlen(gctx->label);
        bufs[idx] = OPENSSL_zalloc(label_len);
        memcpy(bufs[idx], gctx->label, label_len);
        pkcs11_add_attribute(stack, CKA_LABEL, bufs[idx], label_len);
        idx++;
    }

    switch(selection) {
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY:
        pkcs11_add_attribute(stack, CKA_TOKEN, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_CLASS, &priv_key_class, sizeof(priv_key_class));
        pkcs11_add_attribute(stack, CKA_KEY_TYPE, &keytype, sizeof(keytype));
        pkcs11_add_attribute(stack, CKA_PRIVATE, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_MODIFIABLE, &is_false, sizeof(is_false));
        pkcs11_add_attribute(stack, CKA_EXTRACTABLE, &is_false, sizeof(is_false));
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.modulus);
        pkcs11_add_attribute(stack, CKA_MODULUS, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.pubexp);
        pkcs11_add_attribute(stack, CKA_PUBLIC_EXPONENT, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.privexp);
        pkcs11_add_attribute(stack, CKA_PRIVATE_EXPONENT, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.prime1);
        pkcs11_add_attribute(stack, CKA_PRIME_1, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.prime2);
        pkcs11_add_attribute(stack, CKA_PRIME_2, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.exp1);
        pkcs11_add_attribute(stack, CKA_EXPONENT_1, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.exp2);
        pkcs11_add_attribute(stack, CKA_EXPONENT_2, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.coef);
        pkcs11_add_attribute(stack, CKA_COEFFICIENT, bufs[idx], len);
        pkcs11_add_attribute(stack, CKA_UNWRAP, &is_false, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_SIGN, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_DECRYPT, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_DERIVE, &is_false, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_SIGN_RECOVER, &is_true, sizeof(is_true));
        break;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        pkcs11_add_attribute(stack, CKA_TOKEN, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_CLASS, &pub_key_class, sizeof(pub_key_class));
        pkcs11_add_attribute(stack, CKA_KEY_TYPE, &keytype, sizeof(keytype));
        pkcs11_add_attribute(stack, CKA_PRIVATE, &is_false, sizeof(is_false));
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.modulus);
        pkcs11_add_attribute(stack, CKA_MODULUS, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->rsa.pubexp);
        pkcs11_add_attribute(stack, CKA_PUBLIC_EXPONENT, bufs[idx], len);
        pkcs11_add_attribute(stack, CKA_WRAP, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_VERIFY, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_VERIFY_RECOVER, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_ENCRYPT, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_MODIFIABLE, &is_true, sizeof(is_true));
        break;
    default:
        goto end;
    }
    tbl = (CK_ATTRIBUTE *)OPENSSL_zalloc(OPENSSL_sk_num(stack) * sizeof(CK_ATTRIBUTE));
    if (tbl == NULL)
        goto end;

    tbl_len = OPENSSL_sk_num(stack);
    for (i = 0, pattr = tbl; i < tbl_len; i++, pattr++) {
        memcpy(pattr, OPENSSL_sk_value(stack, i), sizeof(CK_ATTRIBUTE));
    }
    rv = pkcs11_get_lib_functions()->C_CreateObject(gctx->session,
                                                    tbl,
                                                    tbl_len, &ret);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(gctx->pkcs11_ctx, rv);
        goto end;
    }

end:
    if (ikey != NULL) {
        CRYPTO_THREAD_write_lock(pkcs11_kemgmt_lock);
        pkcs11_keymgmt_rm_tmp_gen_id(ikey->id, ikey->id_len);
        CRYPTO_THREAD_unlock(pkcs11_kemgmt_lock);
    }

    for (; idx >= 0; idx--)
        OPENSSL_free(bufs[idx]);
    if (tbl)
        OPENSSL_free(tbl);
    if (stack != NULL) {
        for (i = 0; i < tbl_len; i++)
            OPENSSL_free(OPENSSL_sk_pop(stack));
        OPENSSL_sk_free(stack);
    }
    return ret;
}

CK_OBJECT_HANDLE pkcs11_ec_keymgmt_gen_from_import(PKCS11_KEYMGMT_CTX *gctx,
                                                    PKCS11_KEY *ikey, int selection)
{
    CK_OBJECT_HANDLE ret = CK_INVALID_HANDLE;
    CK_BBOOL is_true = CK_TRUE;
    CK_BBOOL is_false = CK_FALSE;
    CK_ULONG pub_key_class = CKO_PUBLIC_KEY;
    CK_ULONG priv_key_class = CKO_PRIVATE_KEY;
    CK_ULONG keytype = CKK_EC;
    unsigned char *bufs[] = {0,0,0,0,0,0,0,0,0,0,0,0};
    size_t len = 0;
    int idx = 0;
    CK_ATTRIBUTE *tbl = NULL;
    size_t tbl_len = 0;
    OPENSSL_STACK *stack = NULL;
    CK_ATTRIBUTE_PTR pattr = NULL;
    CK_RV rv = CKR_CANCEL;
    size_t i = 0;

    stack = OPENSSL_sk_new_null();
    if (gctx->id != NULL && gctx->id_len >0) {
        bufs[idx] = OPENSSL_zalloc(gctx->id_len);
        memcpy(bufs[idx], gctx->id, gctx->id_len);
        pkcs11_add_attribute(stack, CKA_ID, bufs[idx], gctx->id_len);
        idx++;
    }
    if (gctx->label != NULL) {
        int label_len = strlen(gctx->label);
        bufs[idx] = OPENSSL_zalloc(label_len);
        memcpy(bufs[idx], gctx->label, label_len);
        pkcs11_add_attribute(stack, CKA_LABEL, bufs[idx], label_len);
        idx++;
    }

    switch(selection) {
    case OSSL_KEYMGMT_SELECT_PRIVATE_KEY:
        pkcs11_add_attribute(stack, CKA_TOKEN, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_CLASS, &priv_key_class, sizeof(priv_key_class));
        pkcs11_add_attribute(stack, CKA_KEY_TYPE, &keytype, sizeof(keytype));
        pkcs11_add_attribute(stack, CKA_PRIVATE, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_MODIFIABLE, &is_false, sizeof(is_false));
        pkcs11_add_attribute(stack, CKA_EXTRACTABLE, &is_false, sizeof(is_false));
        pkcs11_add_attribute(stack, CKA_SENSITIVE, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_EC_PARAMS, ikey->ecdsa.oid_name,
                             ikey->ecdsa.oid_name_len);
        BN_P11_2_BIN(len, bufs[idx], ikey->ecdsa.pub_point);
        pkcs11_add_attribute(stack, CKA_EC_POINT, bufs[idx], len);
        idx++;
        BN_P11_2_BIN(len, bufs[idx], ikey->ecdsa.priv_value);
        pkcs11_add_attribute(stack, CKA_VALUE, bufs[idx], len);
        pkcs11_add_attribute(stack, CKA_SIGN, &is_true, sizeof(is_true));
        break;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        pkcs11_add_attribute(stack, CKA_TOKEN, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_CLASS, &pub_key_class, sizeof(pub_key_class));
        pkcs11_add_attribute(stack, CKA_KEY_TYPE, &keytype, sizeof(keytype));
        pkcs11_add_attribute(stack, CKA_PRIVATE, &is_false, sizeof(is_false));
        pkcs11_add_attribute(stack, CKA_MODIFIABLE, &is_true, sizeof(is_true));
        pkcs11_add_attribute(stack, CKA_EC_PARAMS, ikey->ecdsa.oid_name,
                             ikey->ecdsa.oid_name_len);
        BN_P11_2_BIN(len, bufs[idx], ikey->ecdsa.pub_point);
        pkcs11_add_attribute(stack, CKA_EC_POINT, bufs[idx], len);
        pkcs11_add_attribute(stack, CKA_VERIFY, &is_true, sizeof(is_true));
        break;
    default:
        goto end;
    }
    tbl = (CK_ATTRIBUTE *)OPENSSL_zalloc(OPENSSL_sk_num(stack) * sizeof(CK_ATTRIBUTE));
    if (tbl == NULL)
        goto end;

    tbl_len = OPENSSL_sk_num(stack);
    for (i = 0, pattr = tbl; i < tbl_len; i++, pattr++) {
        memcpy(pattr, OPENSSL_sk_value(stack, i), sizeof(CK_ATTRIBUTE));
    }
    rv = pkcs11_get_lib_functions()->C_CreateObject(gctx->session,
                                                         tbl,
                                                         tbl_len, &ret);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(gctx->pkcs11_ctx, rv);
        goto end;
    }

end:
    for (; idx >= 0; idx--)
        OPENSSL_free(bufs[idx]);
    if (tbl)
        OPENSSL_free(tbl);
    if (stack != NULL) {
        for (i = 0; i < tbl_len; i++)
            OPENSSL_free(OPENSSL_sk_pop(stack));
        OPENSSL_sk_free(stack);
    }
    return ret;
}

static void *pkcs11_keymgmt_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg)
{
    (void)cb;
    (void)cbarg;
    PKCS11_KEYMGMT_CTX *gctx = (PKCS11_KEYMGMT_CTX*)genctx;
    PKCS11_KEY *key = NULL;
    CK_OBJECT_HANDLE pubkey_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE privkey_handle = CK_INVALID_HANDLE;
    PKCS11_KEY *ret = NULL;
    CK_MECHANISM mech = {0, NULL, 0};
    CK_BBOOL flag_token = CK_TRUE;
    CK_BBOOL flag_true = CK_TRUE;
    CK_RV rv = CKR_OK;
    CK_BYTE *pub_exp = NULL;
    int pub_exp_len = 0;
    CK_ATTRIBUTE *pub_tbl = NULL;
    CK_ATTRIBUTE *priv_tbl = NULL;
    size_t pub_tbl_len = 0;
    size_t priv_tbl_len = 0;
    OPENSSL_STACK *pub_stack = NULL;
    OPENSSL_STACK *priv_stack = NULL;
    size_t i = 0;
    CK_ATTRIBUTE *pattr = NULL;
    CK_BYTE id[PKCS11_DEFAULT_ID_SIZE];
    unsigned char* pmodulus = NULL;
    unsigned char *ppub_exponent = NULL;

    mech.mechanism = gctx->mechdata->type;
    pub_stack = OPENSSL_sk_new_null();
    if (pub_stack == NULL)
        goto end;

    priv_stack = OPENSSL_sk_new_null();
    if (priv_stack == NULL)
        goto end;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        goto end;

    key->prov_ctx = gctx->pkcs11_ctx;

    if (gctx->selection == OSSL_KEYMGMT_SELECT_KEYPAIR) {
        /* Create keypair from parameters */
        if (gctx->id_len > 0 && gctx->id != NULL) {
            key->id = OPENSSL_zalloc(gctx->id_len);
            memcpy(key->id, gctx->id, gctx->id_len);
            key->id_len = gctx->id_len;
        }
        else {
            if (pkcs11_keymgmt_create_id(gctx->pkcs11_ctx, gctx->session, id, sizeof(id)) == 0)
                goto end;
            key->id = OPENSSL_zalloc(PKCS11_DEFAULT_ID_SIZE);
            if (key->id == NULL)
                goto end;

            memcpy(key->id, id, PKCS11_DEFAULT_ID_SIZE);
            key->id_len = PKCS11_DEFAULT_ID_SIZE;
        }
        key->keymgmt_ctx = gctx;

        switch(gctx->type) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            key->type = CKK_RSA;
            if ((pub_exp_len = pkcs11_get_byte_array(gctx->keyparam.rsa.public_exponent,
                                                     &pub_exp)) < 0)
                goto end;
            /* Common storage object attributes */
            pkcs11_add_attribute(pub_stack, CKA_ID, key->id, key->id_len);
            pkcs11_add_attribute(pub_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            /* Common public key attributes */
            pkcs11_add_attribute(pub_stack, CKA_ENCRYPT, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(pub_stack, CKA_VERIFY, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(pub_stack, CKA_WRAP, &flag_true, sizeof(flag_true));
            /* RSA public key object attributes  */
            pkcs11_add_attribute(pub_stack, CKA_MODULUS_BITS,
                                 &gctx->keyparam.rsa.modulus_bits,
                                 sizeof(gctx->keyparam.rsa.modulus_bits));
            pkcs11_add_attribute(pub_stack, CKA_PUBLIC_EXPONENT, pub_exp, pub_exp_len);
            /* Common storage object attributes */
            pkcs11_add_attribute(priv_stack, CKA_ID, key->id, key->id_len);
            pkcs11_add_attribute(priv_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            pkcs11_add_attribute(priv_stack, CKA_PRIVATE, &flag_true, sizeof(flag_true));
            /* Common private key attributes */
            pkcs11_add_attribute(priv_stack, CKA_SENSITIVE, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(priv_stack, CKA_DECRYPT, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(priv_stack, CKA_SIGN, &flag_true, sizeof(flag_true));
            pkcs11_add_attribute(priv_stack, CKA_UNWRAP, &flag_true, sizeof(flag_true));
            break;
        case CKM_ECDSA_KEY_PAIR_GEN:
            key->type = CKK_ECDSA;
            /* Common storage object attributes */
            pkcs11_add_attribute(pub_stack, CKA_ID, key->id, key->id_len);
            pkcs11_add_attribute(pub_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            /* Common public key attributes */
            pkcs11_add_attribute(pub_stack, CKA_EC_PARAMS, gctx->keyparam.ecdsa.oid_name,
                                 gctx->keyparam.ecdsa.oid_name_len);
            /* Common storage object attributes */
            pkcs11_add_attribute(priv_stack, CKA_ID, key->id, key->id_len);
            pkcs11_add_attribute(priv_stack, CKA_TOKEN, &flag_token, sizeof(flag_token));
            pkcs11_add_attribute(priv_stack, CKA_PRIVATE, &flag_true, sizeof(flag_true));
            /* Common private key attributes */
            pkcs11_add_attribute(priv_stack, CKA_SENSITIVE, &flag_true, sizeof(flag_true));
            break;
        default:
            goto end;
        }
        if (gctx->label) {
            pkcs11_add_attribute(pub_stack, CKA_LABEL, gctx->label, strlen(gctx->label));
            pkcs11_add_attribute(priv_stack, CKA_LABEL, gctx->label, strlen(gctx->label));
        }
    }
    else {
        /* Create key from import data */
        if (gctx->import_data == NULL)
            goto end;

        if (gctx->type == CKM_RSA_PKCS_KEY_PAIR_GEN) {
            if (key != NULL)
                OPENSSL_free(key);
            key = (PKCS11_KEY*)gctx->import_data;
            if (gctx->selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
                privkey_handle = pkcs11_rsa_keymgmt_gen_from_import(gctx, key, gctx->selection);
                if (privkey_handle == CK_INVALID_HANDLE)
                    goto end;
            }
            else {
                pubkey_handle = pkcs11_rsa_keymgmt_gen_from_import(gctx, key, gctx->selection);
                if (pubkey_handle == CK_INVALID_HANDLE)
                    goto end;
            }
            if (rv == CKR_OK)
                pkcs11_keymgmt_add_tmp_gen_key(key->id, key->id_len);

            goto key_generated;
        }
    }

    /* Check allocation, change more dynamic attribute tables (primes, exponents may need to be added or not */
    pub_tbl = (CK_ATTRIBUTE *)OPENSSL_zalloc(OPENSSL_sk_num(pub_stack) * sizeof(CK_ATTRIBUTE));
    if (pub_tbl == NULL)
        goto end;

    pub_tbl_len = OPENSSL_sk_num(pub_stack);
    for (i = 0, pattr = pub_tbl; i < pub_tbl_len; i++, pattr++)
        memcpy(pattr, OPENSSL_sk_value(pub_stack, i), sizeof(CK_ATTRIBUTE));

    if (gctx->selection == OSSL_KEYMGMT_SELECT_KEYPAIR) {
        priv_tbl = (CK_ATTRIBUTE *)OPENSSL_zalloc(OPENSSL_sk_num(priv_stack) * sizeof(CK_ATTRIBUTE));
        if (priv_tbl == NULL)
            goto end;

        priv_tbl_len = OPENSSL_sk_num(priv_stack);
        for (i = 0, pattr = priv_tbl; i < priv_tbl_len; i++, pattr++)
            memcpy(pattr, OPENSSL_sk_value(priv_stack, i), sizeof(CK_ATTRIBUTE));
        rv = pkcs11_get_lib_functions()->C_GenerateKeyPair(gctx->session, &mech,
                                                           pub_tbl, pub_tbl_len,
                                                           priv_tbl, priv_tbl_len,
                                                           &pubkey_handle, &privkey_handle);
        if (rv == CKR_OK) {
            /* Added 2 keys, private and public */
            pkcs11_keymgmt_add_tmp_gen_key(key->id, key->id_len);
            pkcs11_keymgmt_add_tmp_gen_key(key->id, key->id_len);
        }
    }

    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(gctx->pkcs11_ctx, rv);
        goto end;
    }

key_generated:
    ret = key;
end:
    if (key != NULL) {
        CRYPTO_THREAD_write_lock(pkcs11_kemgmt_lock);
        pkcs11_keymgmt_rm_tmp_gen_id(key->id, key->id_len);
        CRYPTO_THREAD_unlock(pkcs11_kemgmt_lock);
    }

    if (gctx && gctx->pkcs11_ctx)
        pkcs11_close_session(gctx->pkcs11_ctx, &gctx->session);
    if (!ret) {
        if (key)
            pkcs11_keymgmt_free(key);
    }
    if (pub_tbl)
        OPENSSL_free(pub_tbl);
    if (priv_tbl)
        OPENSSL_free(priv_tbl);
    if (pmodulus)
        OPENSSL_free(pmodulus);
    if (ppub_exponent)
        OPENSSL_free(ppub_exponent);
    if (pub_stack != NULL) {
        for (i = 0; i < pub_tbl_len; i++)
            OPENSSL_free(OPENSSL_sk_pop(pub_stack));
        OPENSSL_sk_free(pub_stack);
    }
    if (priv_stack != NULL) {
        for (i = 0; i < priv_tbl_len; i++)
            OPENSSL_free(OPENSSL_sk_pop(priv_stack));
        OPENSSL_sk_free(priv_stack);
    }
    if (pub_exp)
        OPENSSL_free(pub_exp);

    return ret;
}

static void pkcs11_keymgmt_gen_cleanup(void *genctx)
{
    PKCS11_KEYMGMT_CTX *ctx = (PKCS11_KEYMGMT_CTX *)genctx;
    PKCS11_CTX *provctx = NULL;

    if (ctx != NULL) {
        provctx = (PKCS11_CTX*)ctx->pkcs11_ctx;
        switch(ctx->type) {
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
            BN_free(ctx->keyparam.rsa.public_exponent);
            break;
        case CKM_DES_KEY_GEN:
            break;
        case CKM_ECDSA_KEY_PAIR_GEN:
            OPENSSL_free(ctx->keyparam.ecdsa.oid_name);
            break;
        }
        if (ctx->label)
            OPENSSL_free(ctx->label);
        if (ctx->id)
            OPENSSL_free(ctx->id);
        if (provctx)
            pkcs11_close_session(provctx, &ctx->session);
        OPENSSL_free(ctx);
    }
}

static void pkcs11_keymgmt_clear_keyparam(PKCS11_KEY *pkey)
{
    if (pkey->id)
        OPENSSL_free(pkey->id);
    pkey->id = NULL;

    switch(pkey->type) {
    case CKK_RSA:
        BN_clear_free(pkey->rsa.modulus);
        pkey->rsa.modulus = NULL;
        BN_clear_free(pkey->rsa.pubexp);
        pkey->rsa.pubexp = NULL;
        BN_clear_free(pkey->rsa.privexp);
        pkey->rsa.privexp = NULL;
        BN_clear_free(pkey->rsa.prime1);
        pkey->rsa.prime1 = NULL;
        BN_clear_free(pkey->rsa.prime2);
        pkey->rsa.prime2 = NULL;
        BN_clear_free(pkey->rsa.exp1);
        pkey->rsa.exp1 = NULL;
        BN_clear_free(pkey->rsa.exp2);
        pkey->rsa.exp2 = NULL;
        BN_clear_free(pkey->rsa.coef);
        pkey->rsa.coef = NULL;
        if (pkey->rsa.param_pss)
            OPENSSL_free(pkey->rsa.param_pss);
        pkey->rsa.param_pss = NULL;
        break;
    case CKK_ECDSA:
        if (pkey->ecdsa.oid_name)
            OPENSSL_free(pkey->ecdsa.oid_name);
        pkey->ecdsa.oid_name = NULL;
        BN_clear_free(pkey->ecdsa.pub_point);
        pkey->ecdsa.pub_point = NULL;
        break;
    }
}

static void pkcs11_keymgmt_free(void *keydata)
{
    PKCS11_KEY *pkey = (PKCS11_KEY *)keydata;

    if (pkey == NULL)
        goto end;

    if (pkey->id && pkey->id_len) {
        /* Check if we have to free the key */
        if (pkcs11_keymgmt_rm_tmp_gen_key(pkey->id, pkey->id_len)) {
            CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
            CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
            PKCS11_CTX *ctx = (PKCS11_CTX*)pkey->prov_ctx;
            CK_RV rv = CKR_OK;
            if (pkcs11_open_session(ctx, &session)) {
                obj = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx, pkey, &session);
                if (obj != CK_INVALID_HANDLE) {
                    rv = pkcs11_get_lib_functions()->C_DestroyObject(session, obj);
                    if (rv != CKR_OK) {
                        SET_PKCS11_PROV_ERR(ctx, rv);
                    }
                }
                pkcs11_close_session(ctx, &session);
            }
        }
    }

    pkcs11_keymgmt_clear_keyparam(pkey);

end:
    if (pkey != NULL)
        OPENSSL_free(pkey);
}

/* This get's called to determine which OSSL_STORE_TYPE it will be. */
static int pkcs11_keymgmt_has(const void *keydata, int selection)
{
    PKCS11_KEY *pkey = (PKCS11_KEY *)keydata;
    PKCS11_CTX *ctx = pkey->prov_ctx;
    CK_SESSION_HANDLE session = 0;
    int ok = 0;

    if (pkey == NULL)
        return 0;

    if (ctx == NULL)
        return 0;

    if ((selection &
        (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)) == 0)
        return 1; /* the selection is not missing */

    ok = pkcs11_open_session(ctx, &session);
    if (!ok)
        goto end;

    ok = 0;

    if (selection == OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        if (pkey->is_private)
            goto end;

    if (selection == OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        if (!pkey->is_private)
            goto end;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx, pkey, &session)
                                                       == CK_INVALID_HANDLE)
            goto end;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx, pkey, &session)
                                                       == CK_INVALID_HANDLE)
            goto end;
    }
    ok = 1;
end:
    if (ctx && session)
        pkcs11_close_session(ctx, &session);
    return ok;
}

static int pkcs11_keymgmt_match(const void *keydata1, const void *keydata2, int selection)
{
    const PKCS11_KEY *pkey1 = keydata1;
    const PKCS11_KEY *pkey2 = keydata2;
    PKCS11_CTX *ctx = NULL;
    int ok = 0;

    if (pkey1 == NULL || pkey2 == NULL)
        goto end;

    ctx = pkey1->prov_ctx;
    if (ctx == NULL)
        goto end;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        /* Get import data from both keys to compare with */
        ok = pkcs11_keymgmt_is_key_equal(pkey1, pkey2, 1);
        goto end;
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = pkcs11_keymgmt_is_key_equal(pkey1, pkey2, 1);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = pkcs11_keymgmt_is_key_equal(pkey1, pkey2, 1);
end:
    return ok;
}

static int pkcs11_keymgmt_get_params(void *keydata, OSSL_PARAM params[])
{
    PKCS11_KEY *key = (PKCS11_KEY *)keydata;
    OSSL_PARAM *p = NULL;

    /* Need to add this check. This method gets called from the Store API which
     * doesn't have a keycontext available */
    if (key->keymgmt_ctx != NULL) {
        if (key->keymgmt_ctx->type == CKM_RSA_PKCS_KEY_PAIR_GEN) {
            if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
                 !OSSL_PARAM_set_int(p, key->keymgmt_ctx->keyparam.rsa.modulus_bits))
                return 0;
            if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
                 !OSSL_PARAM_set_int(p, ossl_ifc_ffc_compute_security_bits(key->keymgmt_ctx->keyparam.rsa.modulus_bits)))
                return 0;
            if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
                 !OSSL_PARAM_set_int(p, (key->keymgmt_ctx->keyparam.rsa.modulus_bits)))
                return 0;
        }
    }
    else {
        if (key->type == CKK_RSA) {
            if (key->rsa.modulus == NULL)
                return 0;
            if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL &&
                 !OSSL_PARAM_set_int(p, BN_num_bits(key->rsa.modulus)))
                return 0;
            if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
                 !OSSL_PARAM_set_int(p, ossl_ifc_ffc_compute_security_bits(BN_num_bits(key->rsa.modulus))))
                return 0;
            if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
                 !OSSL_PARAM_set_int(p, BN_num_bits(key->rsa.modulus)))
                return 0;
        }
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        if (key->type == CKK_ECDSA) {
            char *bnhex = NULL;
            int bnhex_size = 0;
            if (key->ecdsa.oid_name == NULL) {
                CK_OBJECT_HANDLE obj = CK_INVALID_HANDLE;
                CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
                int ret = 0;
                ret = pkcs11_open_session(key->prov_ctx, &session);
                if (!ret)
                    return 0;
                key->is_private = 0;
                obj = pkcs11_keymgmt_get_keyhandle_from_keyparam(key->prov_ctx,
                                                                 key, &session);
                if (obj == CK_INVALID_HANDLE)
                    return 0;
                ret = pkcs11_keymgmt_get_keyparam_from_key(key->prov_ctx, key,
                                                           obj, session, key->is_private);
                if (!ret)
                    return 0;
            }

            if (key->is_private) {
                ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY);
                return 0;
            }
            if (key->ecdsa.pub_point == NULL)
                return 0;
            bnhex = BN_bn2hex(key->ecdsa.pub_point);
            bnhex_size = BN_num_bytes(key->ecdsa.pub_point) * 2;
            if (!OSSL_PARAM_set_octet_string(p, bnhex, bnhex_size))
                return 0;
        }
    }

    return 1;
}

static const OSSL_PARAM *pkcs11_keymgmt_gettable_params(void *provctx)
{
    (void)provctx;
    return pkcs11_keymgmt_gettable_params_tbl;
}

static const OSSL_PARAM *pkcs11_keymgmt_gen_settable_params(void *genctx, void *provctx)
{
    (void)genctx;
    (void)provctx;
    return pkcs11_keymgmt_gen_settable_params_tbl;
}

static int pkcs11_keymgmt_get_order_by_ec_oid(CK_BYTE_PTR pp, CK_ULONG len)
{
    int ret = 0;
    CK_BYTE_PTR pparam = NULL;
    int param_len = 0;
    ASN1_OBJECT *obj = NULL;
    int group_nid = 0;
    EC_GROUP *group = NULL;
    BIGNUM *order = BN_new();

    if (len < 3)
        goto end;

    pparam = pp;
    if ((*pparam) != 0x06) /* OID */
        goto end;

    pparam++;
    param_len = *pparam; /* Length of OID */
    if (param_len <= 0)
        goto end;

    pparam++; /* Pointing to the oid data now */

    obj = ASN1_OBJECT_create(0, pparam, param_len, NULL, NULL);
    group_nid = OBJ_obj2nid(obj);

    group = EC_GROUP_new_by_curve_name(group_nid);
    if (group == NULL)
        goto end;

    if (!EC_GROUP_get_order(group, order, NULL))
        goto end;

    ret = BN_num_bytes(order);

end:
    if (order)
        BN_free(order);
    if (group)
        EC_GROUP_free(group);
    if (obj)
        ASN1_OBJECT_free(obj);
    return ret;
}

/* Takes an EC curve name and converts it into an OID. */
static int pkcs11_set_ec_oid_name(CK_BYTE_PTR *pp, const char *name)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(name, 0);
    CK_BYTE_PTR pparam = NULL;
    int ret = 0;

    if (obj == NULL)
        goto end;

    if (pp == NULL)
        goto end;

    (*pp) = OPENSSL_zalloc(OBJ_length(obj) + 2);
    if ((*pp) == NULL)
        goto end;

    ret = OBJ_length(obj) + 2;
    pparam = (*pp);
    *pparam = 0x06; /* OID id */
    pparam++;
    *pparam = OBJ_length(obj); /* Length of OID */
    pparam++;
    /* Set OID data */
    memcpy(pparam, OBJ_get0_data(obj), OBJ_length(obj));
end:
    return ret;
}

static int pkcs11_keymgmt_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    PKCS11_KEYMGMT_CTX *ctx = (PKCS11_KEYMGMT_CTX *)genctx;
    const OSSL_PARAM *p;
    PKCS11_CTX *provctx = NULL;
    PKCS11_TYPE_DATA_ITEM *found = NULL;
    size_t bits = 0;
    int ret = 0;
    char *strval;

    provctx = ctx->pkcs11_ctx;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ALIAS)) != NULL) {
        if (ctx->label)
            OPENSSL_free(ctx->label);
        ctx->label = NULL;
        if (!OSSL_PARAM_get_utf8_string_ptr(p, (const char **)&strval))
            goto end;
        ctx->label = OPENSSL_zalloc(strlen(strval) + 1);
        memcpy(ctx->label, strval, strlen(strval));
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_DIST_ID)) != NULL) {
        size_t id_len = 0;
        if (ctx->id)
            OPENSSL_free(ctx->id);
        ctx->id = NULL;
        if (!OSSL_PARAM_get_octet_string(p, NULL, 0, &id_len))
            goto end;
        ctx->id_len = id_len;
        ctx->id = OPENSSL_zalloc(ctx->id_len);
        if (!OSSL_PARAM_get_octet_string(p, (void **)&ctx->id, ctx->id_len, &id_len))
            goto end;
    }

    switch(ctx->type) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
            if (OSSL_PARAM_get_size_t(p, &bits) != 1)
                goto end;

            /* Find a fitting key manager mechanism */
            found = pkcs11_keymgmt_get_mech_data(provctx, CKM_RSA_PKCS_KEY_PAIR_GEN, bits);
            if (!found)
                goto end;

            ctx->mechdata = found;
            ctx->keyparam.rsa.modulus_bits = bits;
        }
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL) {
            if (ctx->keyparam.rsa.public_exponent)
                BN_free(ctx->keyparam.rsa.public_exponent);
            ctx->keyparam.rsa.public_exponent = NULL;
            if (!OSSL_PARAM_get_BN(p, &ctx->keyparam.rsa.public_exponent))
                goto end;
        }
        break;
    case CKM_ECDSA_KEY_PAIR_GEN:
        if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME)) != NULL) {
            char name[80] = { '\0' };
            if (p->data_type == OSSL_PARAM_UTF8_PTR) {
                if (!OSSL_PARAM_get_utf8_ptr(p, (const char**)&strval))
                    goto end;
            }
            else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
                strval = name;
                if (!OSSL_PARAM_get_utf8_string(p, &strval, sizeof(name)))
                    goto end;
                strval = name;
            }
            if (ctx->keyparam.ecdsa.oid_name != NULL)
                OPENSSL_free(ctx->keyparam.ecdsa.oid_name);
            ctx->keyparam.ecdsa.oid_name_len = pkcs11_set_ec_oid_name(&ctx->keyparam.ecdsa.oid_name,
                                                                      strval);
            ctx->keyparam.ecdsa.order = pkcs11_keymgmt_get_order_by_ec_oid(ctx->keyparam.ecdsa.oid_name,
                                                                           ctx->keyparam.ecdsa.oid_name_len);
        }
        break;
    default:
        goto end;
    }
    ret = 1;
end:
    return ret;
}

OSSL_ALGORITHM *pkcs11_keymgmt_get_algo_tbl(OPENSSL_STACK *sk, const char *id)
{
    OPENSSL_STACK *algo_sk = OPENSSL_sk_new_null();
    OSSL_ALGORITHM *tblalgo = NULL;
    OSSL_ALGORITHM *ptblalgo = NULL;
    OSSL_ALGORITHM* item = NULL;
    int i = 0;
    for (i = 0; i < OPENSSL_sk_num(sk); i++)
    {
        PKCS11_TYPE_DATA_ITEM *item = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(sk, i);
        if (item != NULL) {
            switch(item->type)
            {
            case CKM_RSA_PKCS_KEY_PAIR_GEN:
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_RSA,
                                     id, PKCS11_KEYMGMT_DB_TBL(rsa),
                                     PKCS11_KEYMGMT_ALGO_DESCR(rsa));
                break;
            case CKM_DH_PKCS_KEY_PAIR_GEN:
                break;
            case CKM_ECDSA_KEY_PAIR_GEN:
#ifdef ENABLE_P11_EC
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_EC,
                                     id, PKCS11_KEYMGMT_DB_TBL(ec),
                                     PKCS11_KEYMGMT_ALGO_DESCR(ec));
#endif
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_ECDSA,
                                     id, PKCS11_KEYMGMT_DB_TBL(ec),
                                     PKCS11_KEYMGMT_ALGO_DESCR(ec));
                break;
            }
        }
    }
    i = OPENSSL_sk_num(algo_sk);
    if (i > 0) {
        tblalgo = OPENSSL_zalloc((i + 1) * sizeof(*tblalgo));
        ptblalgo = (OSSL_ALGORITHM *)tblalgo;
        for(; i > 0; i--, ptblalgo++) {
            item = (OSSL_ALGORITHM *)OPENSSL_sk_value(algo_sk, i - 1);
            memcpy(ptblalgo, item, sizeof(*item));
            OPENSSL_free(item);
        }
        OPENSSL_sk_free(algo_sk);
    }
    return tblalgo;
}

static void *pkcs11_keymgmt_load(const void *reference, size_t reference_sz)
{
    PKCS11_STORE_OBJ *store_obj = NULL;
    PKCS11_CTX *ctx = NULL;
    PKCS11_KEY *key = NULL;
    CK_SESSION_HANDLE session = 0;
    int ret = 0;

    if (reference_sz != sizeof(PKCS11_STORE_OBJ))
        goto end;

    store_obj = (PKCS11_STORE_OBJ*)reference;
    if (store_obj == NULL)
        goto end;

    ctx = store_obj->pkcs11_ctx;
    if (ctx == NULL)
        goto end;

    key = pkcs11_keymgmt_newdata(ctx);
    if (key == NULL)
        goto end;

    key->prov_ctx = store_obj->pkcs11_ctx;
    switch (store_obj->obj_class) {
        case CKO_PUBLIC_KEY:
            key->is_private = 0;
        break;
        case CKO_PRIVATE_KEY:
            key->is_private = 1;
        break;
        default:
        break;
    }

    /* Session is created and freed when opens and close store */
    session = store_obj->session;
    ret = pkcs11_keymgmt_get_keyparam_from_key(ctx, key,
                                               store_obj->obj_handle,
                                               session, key->is_private);

end:
    if (!ret) {
        OPENSSL_free(key);
        key = NULL;
    }

    return key;
}

CK_OBJECT_HANDLE pkcs11_keymgmt_get_keyhandle_from_keyparam(PKCS11_CTX* ctx,
                                                            PKCS11_KEY *key,
                                                            CK_SESSION_HANDLE_PTR session)
{
    CK_OBJECT_HANDLE obj_found = CK_INVALID_HANDLE;
    CK_ULONG obj_count = 1;
    CK_RV rv = CKR_OK;
    CK_OBJECT_HANDLE ret = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE find_key[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
    };
    int i = 1;
    /* Index after CKA_KEY_TYPE */
    int alloc_idx = 2;
    int no_retry = 0;

    if (ctx == NULL)
        goto end;

    if (key == NULL)
        goto end;

    if (!key->is_private)
        key_class = CKO_PUBLIC_KEY;

    find_key[i].pValue = &key->type;
    find_key[i].ulValueLen = sizeof(key->type);
    i++;

    if (key->id != NULL) {
        find_key[i].type = CKA_ID;
        find_key[i].pValue = OPENSSL_zalloc(key->id_len);
        find_key[i].ulValueLen = key->id_len;
        memcpy(find_key[i].pValue, key->id, key->id_len);
        i++;
    }
    else {
        switch (key->type) {
        case CKK_RSA:
            find_key[i].type = CKA_MODULUS;
            find_key[i].ulValueLen = BN_num_bytes(key->rsa.modulus);
            find_key[i].pValue = OPENSSL_zalloc(find_key[i].ulValueLen);
            BN_bn2bin(key->rsa.modulus, find_key[i].pValue);
            i++;
            if (key_class == CKO_PUBLIC_KEY) {
                find_key[i].type = CKA_PUBLIC_EXPONENT;
                find_key[i].ulValueLen = BN_num_bytes(key->rsa.pubexp);
                find_key[i].pValue = OPENSSL_zalloc(find_key[i].ulValueLen);
                BN_bn2bin(key->rsa.pubexp, find_key[i].pValue);
                i++;
            }
            break;
        case CKK_ECDSA:
            find_key[i].type = CKA_EC_POINT;
            find_key[i].ulValueLen = BN_num_bytes(key->ecdsa.pub_point);
            find_key[i].pValue = OPENSSL_zalloc(find_key[i].ulValueLen);
            BN_bn2bin(key->ecdsa.pub_point, find_key[i].pValue);
            i++;
            find_key[i].type = CKA_ECDSA_PARAMS;
            find_key[i].ulValueLen = key->ecdsa.oid_name_len;
            find_key[i].pValue = OPENSSL_zalloc(find_key[i].ulValueLen);
            memcpy(find_key[i].pValue, key->ecdsa.oid_name, key->ecdsa.oid_name_len);
            i++;
            break;
        }
    }

try_again:
    /* Some PKCS11 hardware needs to have session closed so the key
     * will be available for querry.
     */
    rv = pkcs11_get_lib_functions()->C_FindObjectsInit(*session,
                                                       find_key, i);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }
    rv = pkcs11_get_lib_functions()->C_FindObjects(*session,
                                                   &obj_found, 1,
                                                   &obj_count);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }

    rv = pkcs11_get_lib_functions()->C_FindObjectsFinal(*session);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }

    if (obj_count < 1) {
        if (no_retry == 0) {
            no_retry = 1;
            pkcs11_close_session(ctx, session);
            pkcs11_open_session(ctx, session);
            goto try_again;
        }
        goto end;
    }

    ret = obj_found;
end:
    for (i--; i >= alloc_idx; i--)
        OPENSSL_clear_free(find_key[i].pValue, find_key[i].ulValueLen);
    return ret;
}

static int pkcs11_keymgmt_is_key_equal(const PKCS11_KEY *pkey1, const PKCS11_KEY *pkey2, int ignorepriv)
{
    int ret = 0;
    if (pkey1 == NULL || pkey2 == NULL)
        goto end;

    if (pkey1->type != pkey2->type)
        goto end;

    switch(pkey1->type){
    case CKK_RSA:
        if (pkey1->rsa.modulus == NULL /*|| pkey1->rsa.pubexp == NULL*/)
            goto end;
        if (pkey2->rsa.modulus == NULL /*|| pkey2->rsa.pubexp == NULL*/)
            goto end;
        if (BN_cmp(pkey1->rsa.modulus, pkey2->rsa.modulus) != 0)
            goto end;
/*        if (BN_cmp(pkey1->rsa.pubexp, pkey2->rsa.pubexp) != 0)
            goto end;*/
        break;
    case CKK_ECDSA:
        if (pkey1->ecdsa.oid_name == NULL || pkey2->ecdsa.oid_name == NULL)
            goto end;
        if (pkey1->ecdsa.oid_name_len != pkey2->ecdsa.oid_name_len)
            goto end;
        if (!pkey1->is_private && !pkey2->is_private) {
            if (pkey2->ecdsa.pub_point == NULL || pkey2->ecdsa.pub_point == NULL)
                goto end;
            if (BN_cmp(pkey1->ecdsa.pub_point, pkey2->ecdsa.pub_point) != 0)
                goto end;
        }
        else {
            if (pkey1->id_len != pkey2->id_len)
                goto end;
            if (pkey1->id_len <= 0)
                goto end;
            if (memcmp(pkey1->id, pkey2->id, pkey1->id_len) != 0)
                goto end;
        }
        if (memcmp(pkey1->ecdsa.oid_name, pkey2->ecdsa.oid_name, pkey1->ecdsa.oid_name_len) != 0)
            goto end;
        break;
    }
    if (ignorepriv != 1)
        if (pkey1->is_private == pkey2->is_private)
            goto end;
    ret = 1;
end:
    return ret;
}

int pkcs11_keymgmt_get_keyparam_from_key(PKCS11_CTX* ctx, PKCS11_KEY *key,
                                         CK_OBJECT_HANDLE keyhandle,
                                         CK_SESSION_HANDLE session,
                                         int is_private)
{
    CK_ULONG keytype = CKK_RSA;
    CK_RV rv;
    int ret = 0;
    int i = 0;
    int use_id = 1;
#define CKA_ID_IDX_KEYPARAM_ATTR 1
    CK_ATTRIBUTE obj_attr[] = {
        {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
        {CKA_ID, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
    };
    int querry_startidx = CKA_ID_IDX_KEYPARAM_ATTR;
    int attr_size = CKA_ID_IDX_KEYPARAM_ATTR + 1;

    if (keyhandle == CK_INVALID_HANDLE)
        goto end;

    /* Querry size needed for some attributes */
    rv = pkcs11_get_lib_functions()->C_GetAttributeValue(session,
                                                         keyhandle, obj_attr,
                                                         attr_size);

    /* Check id ID is defined */
    if (rv != CKR_OK || obj_attr[CKA_ID_IDX_KEYPARAM_ATTR].ulValueLen == 0) {
        use_id = 0;
        attr_size--;
        if (rv !=  CKR_OK)
            rv = pkcs11_get_lib_functions()->C_GetAttributeValue(session,
                                                                 keyhandle, obj_attr,
                                                                 attr_size);
    }

    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }

    switch(keytype) {
    case CKK_RSA:
        obj_attr[attr_size].type = CKA_MODULUS;
        obj_attr[attr_size].pValue = NULL;
        obj_attr[attr_size].ulValueLen = 0;
        attr_size++;
        /* If key is public, get the public exponent */
        if (is_private == CK_FALSE) {
            obj_attr[attr_size].type = CKA_PUBLIC_EXPONENT;
            obj_attr[attr_size].pValue = NULL;
            obj_attr[attr_size].ulValueLen = 0;
            attr_size++;
        }
        break;
    case CKK_ECDSA:
        obj_attr[attr_size].type = CKA_ECDSA_PARAMS;
        obj_attr[attr_size].pValue = NULL;
        obj_attr[attr_size].ulValueLen = 0;
        attr_size++;
        if (is_private == CK_FALSE) {
            obj_attr[attr_size].type = CKA_EC_POINT;
            obj_attr[attr_size].pValue = NULL;
            obj_attr[attr_size].ulValueLen = 0;
            attr_size++;
        }
        break;
    }
    /* Querry size of key type specific attributes */
    rv = pkcs11_get_lib_functions()->C_GetAttributeValue(session,
                                                         keyhandle, obj_attr,
                                                         attr_size);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }

    for (i = querry_startidx; i < attr_size; i++)
        if (obj_attr[i].ulValueLen > 0)
            obj_attr[i].pValue = OPENSSL_zalloc(obj_attr[i].ulValueLen);

    rv = pkcs11_get_lib_functions()->C_GetAttributeValue(session,
                                                         keyhandle, obj_attr,
                                                         attr_size);

    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }

    if (key != NULL)
         pkcs11_keymgmt_clear_keyparam(key);

    if (use_id && obj_attr[CKA_ID_IDX_KEYPARAM_ATTR].ulValueLen > 0) {
        key->id = OPENSSL_zalloc(obj_attr[CKA_ID_IDX_KEYPARAM_ATTR].ulValueLen);
        key->id_len = obj_attr[CKA_ID_IDX_KEYPARAM_ATTR].ulValueLen;
        memcpy(key->id, obj_attr[CKA_ID_IDX_KEYPARAM_ATTR].pValue, key->id_len);
    }

    switch(keytype) {
    case CKK_RSA: {
            int idx = attr_size-1;
            if (is_private == CK_FALSE) {
                key->rsa.pubexp = BN_bin2bn(obj_attr[idx].pValue,
                                            obj_attr[idx].ulValueLen, key->rsa.pubexp);
                idx--;
            }
            key->rsa.modulus = BN_bin2bn(obj_attr[idx].pValue,
                                        obj_attr[idx].ulValueLen, key->rsa.modulus);
        }
        break;
    case CKK_ECDSA: {
            int idx = attr_size-1;
            key->ecdsa.oid_name_len = obj_attr[idx].ulValueLen;
            key->ecdsa.oid_name = OPENSSL_zalloc(key->ecdsa.oid_name_len);
            memcpy(key->ecdsa.oid_name, obj_attr[idx].pValue, key->ecdsa.oid_name_len);
            key->ecdsa.order = pkcs11_keymgmt_get_order_by_ec_oid(key->ecdsa.oid_name,
                                                                  key->ecdsa.oid_name_len);
            idx--;
            if (is_private != CK_TRUE) {
                key->ecdsa.pub_point = BN_bin2bn(obj_attr[idx].pValue,
                                                 obj_attr[idx].ulValueLen, key->ecdsa.pub_point);
            }
        }
        break;
    }
    key->is_private = (is_private == CK_TRUE ? 1 : 0);
    key->type = keytype;

    ret = 1;
end:
    for (i = querry_startidx; i < attr_size; i++) {
        if (obj_attr[i].pValue != NULL)
            OPENSSL_free(obj_attr[i].pValue);
    }
    return ret;
}

int pkcs11_keymgmt_update_key(PKCS11_CTX* ctx, PKCS11_KEY *key,
                              CK_OBJECT_HANDLE keyhandle,
                              CK_SESSION_HANDLE session,
                              char *label, int label_len,
                              unsigned char *id, int id_len)
{
    int ret = 0;
    CK_ATTRIBUTE key_attribs[] = {
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0}};
    int idx = 0;
    CK_RV rv = CKR_CANCEL;

    if (key == NULL)
        goto end;

    /* Setup label */
    if (label != NULL && label_len > 0) {
        key_attribs[idx].type = CKA_LABEL;
        key_attribs[idx].pValue = label;
        key_attribs[idx].ulValueLen = label_len;
        idx++;
    }

    /* Setup ID */
    if (id != NULL && id_len > 0) {
        key_attribs[idx].type = CKA_ID;
        key_attribs[idx].pValue = id;
        key_attribs[idx].ulValueLen = id_len;
        idx++;
    }
    if (idx > 0) {
        rv = pkcs11_get_lib_functions()->C_SetAttributeValue(session, keyhandle,
                                                             key_attribs, idx);
        if (rv == CKR_OK) {
            /* we want to keep this key in the store */
            pkcs11_keymgmt_rm_tmp_gen_key(id, id_len);
        }
        else {
            /* We can't change attributes for private key so we need to delete the old one
             * and create a new one.
             * */
           PKCS11_KEYMGMT_CTX *genctx2 = NULL;
           PKCS11_KEY *tmpkey = NULL;
           int gen_selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
           OSSL_PARAM params[3];
           int paramidx = 0;

           if (key->is_private)
               gen_selection = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
           genctx2 = (PKCS11_KEYMGMT_CTX *)pkcs11_rsa_keymgmt_gen_init(ctx, gen_selection, NULL);
           if (genctx2 == NULL)
               goto end;

           if (id != NULL && id_len > 0) {
               params[paramidx] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DIST_ID, id, id_len);
               paramidx++;
           }
           if (label != NULL && label_len > 0) {
               params[paramidx] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_ALIAS, label, label_len);
               paramidx++;
           }
           params[paramidx] = OSSL_PARAM_construct_end();
           if(paramidx > 0){
               pkcs11_keymgmt_gen_set_params(genctx2, params);
           }
           genctx2->import_data = key;
           tmpkey = pkcs11_keymgmt_gen(genctx2, NULL, NULL);
           /* tmpkey is same as key. Will be frees when OSSL Store info object frees. */
           if (tmpkey) {
               /* We want to keep this key in the store */
               pkcs11_keymgmt_rm_tmp_gen_key(tmpkey->id, tmpkey->id_len);
               rv = pkcs11_get_lib_functions()->C_DestroyObject(session, keyhandle);
           }
           pkcs11_keymgmt_gen_cleanup(genctx2);
        }
    }
    ret = 1;
end:

    return ret;
}

