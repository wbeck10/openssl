#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/stack.h>
#include <openssl/objects.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include <internal/provider.h>
#include "pkcs11_kmgmt.h"
#include "pkcs11_ctx.h"
#include "pkcs11_utils.h"
#include <internal/sizes.h>
#include <openssl/prov_ssl.h>
#include <openssl/err.h>
#include <openssl/proverr.h>

/* Implement all ciphers they support en- / decrypting */
/* Private functions */

PKCS11_TYPE_DATA_ITEM *pkcs11_asym_cipher_get_mech_data(PKCS11_CTX *provctx,
                                                        PKCS11_CIPHER_CTX *ctx,
                                                        CK_MECHANISM *mech);
static int pkcs11_asym_cipher_required_length(PKCS11_CIPHER_CTX *ctx, size_t *len);

static OSSL_FUNC_asym_cipher_newctx_fn
                            pkcs11_asym_cipher_newctx;
static OSSL_FUNC_asym_cipher_encrypt_fn
                            pkcs11_asym_cipher_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_fn
                            pkcs11_asym_cipher_decrypt;
static OSSL_FUNC_asym_cipher_freectx_fn
                            pkcs11_asym_cipher_freectx;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn
                            pkcs11_asym_cipher_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn
                            pkcs11_asym_cipher_get_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn
                            pkcs11_asym_cipher_settable_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn
                            pkcs11_asym_cipher_set_ctx_params;

struct pkcs11_asym_cipher_map_st{
    unsigned long mechanics;
    const char* SN;
    int nid;
    const OSSL_DISPATCH *table;
};

typedef struct pkcs11_asym_cipher_map_st PKCS11_ASYM_CIPHER_MAP;
static int pkcs11_asym_cipher_encrypt_default_init(void *ctx, void *provkey, const OSSL_PARAM params[],
                                      unsigned long type, int nid);
static int pkcs11_asym_cipher_decrypt_default_init(void *ctx, void *provkey, const OSSL_PARAM params[],
                                      unsigned long type, int nid);

#define PKCS11_ASYM_CIPHER_rsa_algo_descr          "PKCS11 asym cipher rsa algo"
#define PKCS11_ASYM_CIPHER_ALGO_DESCR(name)        pkcs11_asym_cipher_##name##_algo_description
#define PKCS11_ASYM_CIPHER_INIT_FCT(name)          pkcs11_asym_cipher_##name##_init
#define PKCS11_ASYM_CIPHER_GET_CTX_PARAM_FCT(name) pkcs11_asym_cipher_##name##_get_ctx_params
#define PKCS11_ASYM_CIPHER_DB_TBL(name)            pkcs11_asym_cipher_##name##_dp_tbl
#define PKCS11_ASYM_CIPHER_ENCRYPT_INIT_FCT(name)  pkcs11_asym_cipher_##name##_encrypt_init
#define PKCS11_ASYM_CIPHER_DECRYPT_INIT_FCT(name)  pkcs11_asym_cipher_##name##_decrypt_init

#define PKCS11_PROV_FUNC_ASYM_CIPHER(name, ckmid, nid)               \
/* Define Algorith description */                               \
static char* PKCS11_ASYM_CIPHER_ALGO_DESCR(name) = PKCS11_ASYM_CIPHER_##name##_algo_descr; \
/* define the init function for the specific asym cipher */                             \
static int PKCS11_ASYM_CIPHER_ENCRYPT_INIT_FCT(name)(void *ctx, void *provkey, const OSSL_PARAM params[])     \
{                                                                                       \
    return pkcs11_asym_cipher_encrypt_default_init(ctx, provkey, params, ckmid, nid);                   \
}                                                                                       \
static int PKCS11_ASYM_CIPHER_DECRYPT_INIT_FCT(name)(void *ctx, void *provkey, const OSSL_PARAM params[])     \
{                                                                                       \
    return pkcs11_asym_cipher_decrypt_default_init(ctx, provkey, params, ckmid, nid);                   \
}                                                                                       \
/* define the dispatch table for the specific digest */                                 \
const OSSL_DISPATCH PKCS11_ASYM_CIPHER_DB_TBL(name)[] = {                                                \
    { OSSL_FUNC_ASYM_CIPHER_NEWCTX,          (void (*)(void))pkcs11_asym_cipher_newctx },                \
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,    (void (*)(void))PKCS11_ASYM_CIPHER_ENCRYPT_INIT_FCT(name) },        \
    { OSSL_FUNC_ASYM_CIPHER_ENCRYPT,         (void (*)(void))pkcs11_asym_cipher_encrypt },                \
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,    (void (*)(void))PKCS11_ASYM_CIPHER_DECRYPT_INIT_FCT(name) },        \
    { OSSL_FUNC_ASYM_CIPHER_DECRYPT,         (void (*)(void))pkcs11_asym_cipher_decrypt },                \
    { OSSL_FUNC_ASYM_CIPHER_FREECTX,         (void (*)(void))pkcs11_asym_cipher_freectx },                 \
    { OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,  (void (*)(void))pkcs11_asym_cipher_get_ctx_params },   \
    { OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))pkcs11_asym_cipher_gettable_ctx_params },       \
    { OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,  (void (*)(void))pkcs11_asym_cipher_set_ctx_params },   \
    { OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))pkcs11_asym_cipher_settable_ctx_params },       \
    {0, NULL}                                                                                       \
};

PKCS11_PROV_FUNC_ASYM_CIPHER(rsa,     CKM_RSA_PKCS,      NID_rsa)

const PKCS11_ASYM_CIPHER_MAP pkcs11_asym_cipher_map[] = {
    /* Don't list oaep or other padding, this will be handled in context parameter settings */
    {CKM_RSA_PKCS,      SN_rsa,       NID_rsa,       PKCS11_ASYM_CIPHER_DB_TBL(rsa)},
    {0, NULL, 0, NULL}
};

static const OSSL_PARAM pkcs11_asym_cipher_gettable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM pkcs11_asym_cipher_settable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL, 0),
    OSSL_PARAM_END
};

static void *pkcs11_asym_cipher_newctx(void *provctx)
{
    PKCS11_CTX *pctx = (PKCS11_CTX *)provctx;
    PKCS11_CIPHER_CTX *ctx = NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        SET_PKCS11_PROV_ERR(pctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        return NULL;
    }
    ctx->pkcs11_ctx = pctx;

    return ctx;
}

static int pkcs11_asym_cipher_encrypt_default_init(void *cctx, void *provkey, const OSSL_PARAM params[],
                                      unsigned long type, int nid)
{
    PKCS11_CIPHER_CTX *ctx = (PKCS11_CIPHER_CTX *)cctx;
    PKCS11_KEY *pkey = (PKCS11_KEY *)provkey;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if (pkey == NULL)
        goto end;

    ctx->type = type;
    ctx->nid = nid;
    ctx->isinit = 1;
    /* Set default padding mode for RSA */
    if (nid == NID_rsa)
        ctx->padmode = PKCS11_RSA_PKCS_PADDING;
    pkey->is_private = 0;
    ctx->pkey = pkey;
    pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    ret = pkcs11_open_session(ctx->pkcs11_ctx, &ctx->session);
end:
    if (ret == 0) {
        if (ctx)
            pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    }
    return ret;
}

static int pkcs11_asym_cipher_encrypt(void *cctx, unsigned char *out,
                                      size_t *outlen,
                                      size_t outsize,
                                      const unsigned char *in,
                                      size_t inlen)
{
    PKCS11_CIPHER_CTX *ctx = (PKCS11_CIPHER_CTX *)cctx;
    CK_RV rv = CKR_OK;
    CK_ULONG ulinlen = inlen;
    CK_ULONG uloutlen = *outlen;
    CK_MECHANISM mech = {0, NULL, 0};
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if (ctx->isinit) {
        CK_OBJECT_HANDLE keyhandle = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx->pkcs11_ctx,
                                                                                ctx->pkey,
                                                                                &ctx->session);
        if (keyhandle == CK_INVALID_HANDLE)
            goto end;

        ctx->mechdata = pkcs11_asym_cipher_get_mech_data(ctx->pkcs11_ctx,
                                                         ctx,
                                                         &mech);
        if (ctx->mechdata == NULL)
            goto end;

        mech.mechanism = ctx->mechdata->type;
        rv = pkcs11_get_lib_functions()->C_EncryptInit(ctx->session,
                                                       &mech, keyhandle);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 0;
    }

    if (out == NULL) {
        ret = pkcs11_asym_cipher_required_length(ctx, outlen);
        goto end;
    }

    rv = pkcs11_get_lib_functions()->C_Encrypt(ctx->session,
                                               (CK_BYTE_PTR)in, ulinlen,
                                               (CK_BYTE_PTR)out, &uloutlen);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    *outlen = (size_t)uloutlen;
    ret = 1;
end:
    if (mech.pParameter)
        OPENSSL_free(mech.pParameter);
    return ret;
}

static int pkcs11_asym_cipher_decrypt_default_init(void *cctx, void *provkey, const OSSL_PARAM params[],
                                      unsigned long type, int nid)
{
    PKCS11_CIPHER_CTX *ctx = (PKCS11_CIPHER_CTX *)cctx;
    PKCS11_KEY *pkey = (PKCS11_KEY *)provkey;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if (pkey == NULL)
        goto end;

    ctx->type = type;
    ctx->nid = nid;
    ctx->isinit = 1;
    /* Set default padding mode for RSA */
    if (nid == NID_rsa)
        ctx->padmode = PKCS11_RSA_PKCS_PADDING;
    pkey->is_private = 1;
    ctx->pkey = pkey;
    pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    ret = pkcs11_open_session(ctx->pkcs11_ctx, &ctx->session);
end:
    if (ret == 0) {
        if (ctx)
            pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    }
    return ret;
}

static int pkcs11_asym_cipher_decrypt_rsa_with_tls_padding(PKCS11_CIPHER_CTX *ctx,
                                                           unsigned char *out,
                                                           size_t *outlen,
                                                           size_t outsize,
                                                           const unsigned char *in,
                                                           size_t inlen)
{
    int ret = 0;
    unsigned char *tbuf = NULL;
    CK_ULONG len = BN_num_bytes(ctx->pkey->rsa.modulus);
    CK_RV rv = CKR_CANCEL;
    CK_ULONG ulinlen = inlen;

    if (ctx->padmode == PKCS11_RSA_PKCS1_WITH_TLS_PADDING) {
        if (out == NULL) {
            *outlen = SSL_MAX_MASTER_KEY_LENGTH;
            return 1;
        }
        if (outsize < SSL_MAX_MASTER_KEY_LENGTH) {
            ERR_raise(ERR_LIB_PROV, PROV_R_BAD_LENGTH);
            return 0;
        }
    }
    /* Create a buffer with modulus size */
    len = BN_num_bytes(ctx->pkey->rsa.modulus);

    if ((tbuf = OPENSSL_malloc(len)) == NULL)
        return 0;

    rv = pkcs11_get_lib_functions()->C_Decrypt(ctx->session,
                                               (CK_BYTE_PTR)in, ulinlen,
                                               (CK_BYTE_PTR)tbuf, &len);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    ret = ossl_rsa_padding_check_PKCS1_type_2_TLS(ctx->pkcs11_ctx->ctx.libctx,
                                                  out, outsize, tbuf, len,
                                                  ctx->client_version, ctx->alt_version);

    goto end;

end:
    if (tbuf)
        OPENSSL_free(tbuf);
    return ret;
}

static int pkcs11_asym_cipher_decrypt(void *cctx, unsigned char *out,
                                      size_t *outlen,
                                      size_t outsize,
                                      const unsigned char *in,
                                      size_t inlen)
{
    PKCS11_CIPHER_CTX *ctx = (PKCS11_CIPHER_CTX *)cctx;
    CK_RV rv = CKR_OK;
    CK_ULONG ulinlen = inlen;
    CK_ULONG uloutlen = *outlen;
    CK_MECHANISM mech = {0, NULL, 0};
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if (ctx->isinit) {
        CK_OBJECT_HANDLE keyhandle = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx->pkcs11_ctx,
                                                                                ctx->pkey,
                                                                                &ctx->session);
        if (keyhandle == CK_INVALID_HANDLE)
            goto end;

        ctx->mechdata = pkcs11_asym_cipher_get_mech_data(ctx->pkcs11_ctx,
                                                         ctx,
                                                         &mech);
        if (ctx->mechdata == NULL)
            goto end;
        mech.mechanism = ctx->mechdata->type;
        rv = pkcs11_get_lib_functions()->C_DecryptInit(ctx->session,
                                                       &mech, keyhandle);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 0;
    }

    if (ctx->padmode == PKCS11_RSA_PKCS1_WITH_TLS_PADDING) {
        ret = pkcs11_asym_cipher_decrypt_rsa_with_tls_padding(ctx, out, outlen,outsize,in,inlen);
        goto end;
    }

    if (out == NULL) {
        ret = pkcs11_asym_cipher_required_length(ctx, outlen);
        goto end;
    }

    rv = pkcs11_get_lib_functions()->C_Decrypt(ctx->session,
                                               (CK_BYTE_PTR)in, ulinlen,
                                               (CK_BYTE_PTR)out, &uloutlen);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    *outlen = (size_t)uloutlen;
    ret = 1;
end:
    if (mech.pParameter)
        OPENSSL_free(mech.pParameter);
    return ret;
}

static const OSSL_PARAM *pkcs11_asym_cipher_gettable_ctx_params(ossl_unused void *ctx,
                                                                ossl_unused void *provctx)
{
    return pkcs11_asym_cipher_gettable_ctx_params_tbl;
}

static int pkcs11_asym_cipher_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    PKCS11_CIPHER_CTX *cctx = (PKCS11_CIPHER_CTX*)ctx;
    OSSL_PARAM *p;

    if (cctx && params) {
        p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
        if (p != NULL) {
            switch(p->data_type) {
            case OSSL_PARAM_INTEGER:
                switch(cctx->padmode) {
                    case PKCS11_RSA_PKCS_PADDING:
                        OSSL_PARAM_set_int(p, RSA_PKCS1_PADDING);
                    break;
                    case PKCS11_RSA_PKCS_OAEP_PADDING:
                        OSSL_PARAM_set_int(p, RSA_PKCS1_OAEP_PADDING);
                    break;
                    case PKCS11_RSA_PKCS1_WITH_TLS_PADDING:
                        OSSL_PARAM_set_int(p, RSA_PKCS1_WITH_TLS_PADDING);
                    break;
                    default:
                        return 0;
                }
            case OSSL_PARAM_UTF8_STRING:
                switch(cctx->padmode) {
                    case PKCS11_RSA_PKCS_PADDING:
                        OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PAD_MODE_PKCSV15);
                    break;
                    case PKCS11_RSA_PKCS_OAEP_PADDING:
                        OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PAD_MODE_OAEP);
                    break;
                    default:
                        return 0;
                }
                break;
            }
        }
        p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
        if (p != NULL && !OSSL_PARAM_set_uint(p, cctx->client_version))
            return 0;

        p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
        if (p != NULL && !OSSL_PARAM_set_uint(p, cctx->alt_version))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *pkcs11_asym_cipher_settable_ctx_params(ossl_unused void *ctx, ossl_unused void *provctx)
{
    return pkcs11_asym_cipher_settable_ctx_params_tbl;
}

static int pkcs11_asym_cipher_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    PKCS11_CIPHER_CTX *cctx = (PKCS11_CIPHER_CTX*)ctx;
    const OSSL_PARAM *p;
    char *str = NULL;

    if (cctx && params) {
        p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
        if (p != NULL) {
            switch (p->data_type) {
            case OSSL_PARAM_INTEGER: /* Support for legacy pad mode number */
                {
                    int padmod = 0;
                    if (!OSSL_PARAM_get_int(p, &padmod))
                        return 0;
                    switch (padmod) {
                        case RSA_PKCS1_PADDING:
                            cctx->padmode = PKCS11_RSA_PKCS_PADDING;
                            break;
                        case RSA_PKCS1_OAEP_PADDING:
                            cctx->padmode = PKCS11_RSA_PKCS_OAEP_PADDING;
                            if (cctx->nid_md == 0)
                                cctx->nid_md = pkcs11_md_nid2ckm(NID_sha256);
                            if (cctx->nid_md_mgf1 == 0)
                                cctx->nid_md_mgf1 = pkcs11_md_nid2ckm_mgf1(NID_sha256);
                            break;
                        case RSA_PKCS1_WITH_TLS_PADDING:
                            cctx->padmode = PKCS11_RSA_PKCS1_WITH_TLS_PADDING;
                            break;
                        default:
                            return 0;
                    }
                }
                break;
            case OSSL_PARAM_UTF8_STRING:
                if (!OSSL_PARAM_get_utf8_ptr(p, (const  char**)&str))
                    return 0;
                if (strcmp(str, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
                    cctx->padmode = PKCS11_RSA_PKCS_PADDING;
                else if (strcmp(str, OSSL_PKEY_RSA_PAD_MODE_OAEP) == 0) {
                    cctx->padmode = PKCS11_RSA_PKCS_OAEP_PADDING;
                    if (cctx->nid_md == 0)
                        cctx->nid_md = pkcs11_md_nid2ckm(NID_sha256);
                    if (cctx->nid_md_mgf1 == 0)
                        cctx->nid_md_mgf1 = pkcs11_md_nid2ckm_mgf1(NID_sha256);
                }
                else
                    return  0;
            default:
                return 0;
            }
        }
        p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
        if (p != NULL) {
            char mdname[OSSL_MAX_NAME_SIZE];
            str = mdname;
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdname)))
                return 0;
            cctx->nid_md = pkcs11_find_mdnid_by_name(mdname);
        }
        p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
        if (p != NULL) {
            char mdname[OSSL_MAX_NAME_SIZE];
            str = mdname;
            if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdname)))
                return 0;
            cctx->nid_md_mgf1 = pkcs11_find_mdnid_by_name(mdname);
        }
        p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
        if (p != NULL) {
            unsigned int client_version;
            if (!OSSL_PARAM_get_uint(p, &client_version))
                return 0;
            cctx->client_version = client_version;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
        if (p != NULL) {
            unsigned int alt_version;

            if (!OSSL_PARAM_get_uint(p, &alt_version))
                return 0;
            cctx->alt_version = alt_version;
        }
        return 1;
    }
    return 0;
}

static void pkcs11_asym_cipher_freectx(void *cctx)
{
    PKCS11_CIPHER_CTX *ctx = (PKCS11_CIPHER_CTX *)cctx;

    if (ctx != NULL)
        pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    OPENSSL_free(ctx);
}

OSSL_ALGORITHM *pkcs11_asym_cipher_get_algo_tbl(OPENSSL_STACK *sk, const char *id)
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
            switch(item->type) {
            case CKM_RSA_PKCS:
            case CKM_RSA_PKCS_OAEP:
            if ((item->info.flags | CKF_DECRYPT) && (item->info.flags | CKF_ENCRYPT)) {
                const PKCS11_ASYM_CIPHER_MAP* pdm = pkcs11_asym_cipher_map;
                for(;pdm->mechanics != 0;pdm++){
                    if (item->type == pdm->mechanics) {
                        pkcs11_add_algorithm(algo_sk, pdm->SN, id, pdm->table,
                                             PKCS11_ASYM_CIPHER_ALGO_DESCR(rsa));
                    }
                }
            }
                break;
            default:
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

PKCS11_TYPE_DATA_ITEM *pkcs11_asym_cipher_get_mech_data(PKCS11_CTX *provctx,
                                                        PKCS11_CIPHER_CTX *ctx,
                                                        CK_MECHANISM *mech)
{
    int i = 0;
    PKCS11_SLOT *slot = NULL;
    PKCS11_TYPE_DATA_ITEM *pcipher = NULL;
    CK_RSA_PKCS_OAEP_PARAMS *oaep_param = NULL;
    CK_MECHANISM_TYPE type = ctx->type;
    int padmode = ctx->padmode;
    CK_MECHANISM_TYPE matchtype = type;

    /* In case of RSA we need to consider the pad mode */
    if (type == CKM_RSA_PKCS) {
        switch (padmode) {
        case PKCS11_RSA_PKCS_PADDING:
            matchtype = CKM_RSA_PKCS;
            break;
        case PKCS11_RSA_PKCS_OAEP_PADDING:
            matchtype = CKM_RSA_PKCS_OAEP;
            mech->ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
            oaep_param = OPENSSL_zalloc(mech->ulParameterLen);
            oaep_param->hashAlg = pkcs11_md_nid2ckm(ctx->nid_md);
            oaep_param->mgf = pkcs11_md_nid2ckm_mgf1(ctx->nid_md_mgf1);
            mech->pParameter = oaep_param;
            break;
        case PKCS11_RSA_PKCS1_WITH_TLS_PADDING:
            matchtype = CKM_RSA_X_509;
            break;
        }
    }

    slot = pkcs11_get_slot(provctx);
    if (slot) {
        for (i = 0; i < OPENSSL_sk_num(slot->asym_cipher.items); i++) {
            pcipher = (PKCS11_TYPE_DATA_ITEM *)OPENSSL_sk_value(slot->asym_cipher.items, i);
            if (pcipher->type == matchtype)
                return pcipher;
        }
    }
    return NULL;
}

static int pkcs11_asym_cipher_required_length(PKCS11_CIPHER_CTX *ctx, size_t *len)
{
    if (ctx->type == CKM_RSA_PKCS || ctx->type == CKM_RSA_PKCS_PSS) {
        (*len) = BN_num_bytes(ctx->pkey->rsa.modulus);
        return 1;
    }
    return 0;
}
