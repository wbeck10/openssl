#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/stack.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include "pkcs11_kmgmt.h"
#include "pkcs11_ctx.h"
#include "pkcs11_utils.h"
#include <openssl/err.h>
#include "../../include/internal/packet.h"

/* Private functions */
CK_ULONG pkcs11_signature_get_mech_data(PKCS11_SIGN_CTX *ctx, CK_MECHANISM *mech);
static int pkcs11_signature_required_length(PKCS11_SIGN_CTX *ctx, size_t *len);
CK_ULONG pkcs11_signature_get_mgf1_salt_len(PKCS11_SIGN_CTX *ctx);
extern int ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption(WPACKET *pkt, int tag,
                                                              int mdnid);
extern int ossl_DER_w_algorithmIdentifier_RSA_PSS(WPACKET *pkt, int tag,
                                                  int rsa_type,
                                                  const RSA_PSS_PARAMS_30 *pss);

static OSSL_FUNC_signature_newctx_fn                    pkcs11_signature_newctx;
static OSSL_FUNC_signature_sign_init_fn                 pkcs11_signature_rsa_sign_init;
static OSSL_FUNC_signature_sign_init_fn                 pkcs11_signature_ecdsa_sign_init;
static OSSL_FUNC_signature_sign_fn                      pkcs11_signature_sign;
static OSSL_FUNC_signature_verify_init_fn               pkcs11_signature_rsa_verify_init;
static OSSL_FUNC_signature_verify_init_fn               pkcs11_signature_ecdsa_verify_init;
static OSSL_FUNC_signature_verify_fn                    pkcs11_signature_verify;
static OSSL_FUNC_signature_freectx_fn                   pkcs11_signature_freectx;
static OSSL_FUNC_signature_dupctx_fn                    pkcs11_signature_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn            pkcs11_signature_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn       pkcs11_signature_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn            pkcs11_signature_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn       pkcs11_signature_settable_ctx_params;
static OSSL_FUNC_signature_digest_sign_init_fn          pkcs11_signature_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_fn               pksc11_signature_digest_sign;
static OSSL_FUNC_signature_digest_sign_update_fn        pkcs11_signature_digest_sign_update;
static OSSL_FUNC_signature_digest_sign_final_fn         pkcs11_signature_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn        pkcs11_signature_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_fn             pkcs11_signature_digest_verify;
static OSSL_FUNC_signature_digest_verify_update_fn      pkcs11_signature_digest_verify_update;
static OSSL_FUNC_signature_digest_verify_final_fn       pkcs11_signature_digest_verify_final;

#define PKCS11_SIGNATURE_rsa_algo_descr          "PKCS11 signature rsa algo"
#define PKCS11_SIGNATURE_ecdsa_algo_descr        "PKCS11 signature ecdsa algo"
#define PKCS11_SIGNATURE_ALGO_DESCR(name)        pkcs11_signature_##name##_algo_description
#define PKCS11_SIGNATURE_SIGN_INIT_FCT(name)     pkcs11_signature_##name##_sign_init
#define PKCS11_SIGNATURE_VERIFY_INIT_FCT(name)   pkcs11_signature_##name##_verify_init
#define PKCS11_SIGNATURE_DB_TBL(name)            pkcs11_##name##_sign_dp_tbl

#define PKCS11_PROV_FUNC_SIGNATURE(name)                        \
/* Define Algorith description */                               \
static char* PKCS11_SIGNATURE_ALGO_DESCR(name) = PKCS11_SIGNATURE_##name##_algo_descr; \
/* define the init function for the specific signature */       \
const OSSL_DISPATCH PKCS11_SIGNATURE_DB_TBL(name)[] = {         \
    { OSSL_FUNC_SIGNATURE_NEWCTX,                               \
        (void (*)(void))pkcs11_signature_newctx },              \
    { OSSL_FUNC_SIGNATURE_SIGN_INIT,                            \
        (void (*)(void))PKCS11_SIGNATURE_SIGN_INIT_FCT(name) }, \
    { OSSL_FUNC_SIGNATURE_SIGN,                                 \
        (void (*)(void))pkcs11_signature_sign },                \
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT,                          \
        (void (*)(void))PKCS11_SIGNATURE_VERIFY_INIT_FCT(name) }, \
    { OSSL_FUNC_SIGNATURE_VERIFY,                               \
        (void (*)(void))pkcs11_signature_verify },              \
    { OSSL_FUNC_SIGNATURE_FREECTX,                              \
        (void (*)(void))pkcs11_signature_freectx },             \
    { OSSL_FUNC_SIGNATURE_DUPCTX,                               \
        (void (*)(void))pkcs11_signature_dupctx },              \
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                       \
        (void (*)(void))pkcs11_signature_get_ctx_params },      \
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                  \
        (void (*)(void))pkcs11_signature_gettable_ctx_params }, \
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                       \
        (void (*)(void))pkcs11_signature_set_ctx_params },      \
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                  \
        (void (*)(void))pkcs11_signature_settable_ctx_params }, \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                     \
        (void (*)(void))pkcs11_signature_digest_sign_init },    \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,                          \
        (void (*)(void))pksc11_signature_digest_sign },         \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,                   \
        (void (*)(void))pkcs11_signature_digest_sign_update },  \
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,                    \
        (void (*)(void))pkcs11_signature_digest_sign_final },   \
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,                   \
        (void (*)(void))pkcs11_signature_digest_verify_init },  \
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,                        \
        (void (*)(void))pkcs11_signature_digest_verify },       \
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,                 \
        (void (*)(void))pkcs11_signature_digest_verify_update }, \
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,                  \
        (void (*)(void))pkcs11_signature_digest_verify_final }, \
};

PKCS11_PROV_FUNC_SIGNATURE(rsa)
PKCS11_PROV_FUNC_SIGNATURE(ecdsa)

static const OSSL_PARAM pkcs11_sign_gettable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM pkcs11_sign_settable_ctx_params_tbl[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static void *pkcs11_signature_newctx(void *provctx, const char *propq)
{
    (void)propq;
    PKCS11_CTX *pctx = (PKCS11_CTX *)provctx;
    PKCS11_SIGN_CTX *ctx = NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        SET_PKCS11_PROV_ERR(pctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->pkcs11_ctx = pctx;
    ctx->pss_salt_len = RSA_PSS_SALTLEN_AUTO;

    return ctx;
}

static int pkcs11_signature_rsa_sign_init(void *sigctx, void *vrsa, const OSSL_PARAM params[])
{
    (void)params;
    PKCS11_KEY *pkey = (PKCS11_KEY *)vrsa;
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if (pkey == NULL)
        goto end;

    pkey->is_private = 1;
    ctx->pkey = pkey;
    ctx->type = CKM_RSA_PKCS;
    ctx->nid_md = NID_sha256;
    ctx->nid_md_mgf1 = NID_sha256;
    ctx->isinit = 1;

    ret = pkcs11_open_session(ctx->pkcs11_ctx, &ctx->session);
end:
    if (ret == 0){
        if (ctx)
            pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    }
    return ret;
}

static int pkcs11_signature_ecdsa_sign_init(void *sigctx, void *vecdsa, const OSSL_PARAM params[])
{
    (void)params;
    PKCS11_KEY *pkey = (PKCS11_KEY *)vecdsa;
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    pkey->is_private = 1;
    ctx->pkey = pkey;
    ctx->type = CKM_ECDSA;
    ctx->nid_md = NID_sha256;
    ctx->isinit = 1;

    ret = pkcs11_open_session(ctx->pkcs11_ctx, &ctx->session);
    if (ret == 0)
        goto end;

    ret = 1;
end:
    if (ret == 0){
        if (ctx)
            pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    }
    return ret;
}

static int pkcs11_signature_sign(void *sigctx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    /* todo call pkcs hw to do signing */
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    CK_MECHANISM mech = {0, NULL, 0};
    CK_RV rv = CKR_OK;
    CK_ULONG cksiglen = sigsize;
    CK_BYTE_PTR psig = (CK_BYTE_PTR)sig;
    CK_BYTE_PTR ptbs = (CK_BYTE_PTR)tbs;
    int ret = 0;

    if (!ctx)
        goto end;

    mech.mechanism = pkcs11_signature_get_mech_data(ctx, &mech);
    if (mech.mechanism == CKM_NULL)
        goto end;

    if (ctx->isinit) {
        CK_OBJECT_HANDLE keyhandle = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx->pkcs11_ctx,
                                                                                ctx->pkey,
                                                                                &ctx->session);
        if (keyhandle == CK_INVALID_HANDLE)
            goto end;

        /* Initialize with padding mode */
        rv = pkcs11_get_lib_functions()->C_SignInit(ctx->session,
                                                    &mech, keyhandle);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 0;
    }

    if (psig == NULL) {
        ret = pkcs11_signature_required_length(ctx, siglen);
        if (ret)
            goto end;
    }

    rv = pkcs11_get_lib_functions()->C_Sign(ctx->session,
                                            ptbs, tbslen, psig, &cksiglen);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    *siglen = cksiglen;
    ret = 1;
end:
    if (mech.pParameter != NULL)
        OPENSSL_free(mech.pParameter);
    return ret;
}

static int pkcs11_signature_rsa_verify_init(void *sigctx, void *vrsa,
                           const OSSL_PARAM params[])
{
    (void)params;
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    PKCS11_KEY *pkey = (PKCS11_KEY *)vrsa;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if (pkey == NULL)
        goto end;

    pkey->is_private = 0;
    ctx->pkey = pkey;
    ctx->type = CKM_RSA_PKCS;
    ctx->isinit = 1;
    ret = pkcs11_open_session(ctx->pkcs11_ctx, &ctx->session);
end:
    if (ret == 0){
        if (ctx)
            pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    }
    return ret;
}

static int pkcs11_signature_ecdsa_verify_init(void *sigctx, void *vecdsa,
                           const OSSL_PARAM params[])
{
    (void)params;
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    PKCS11_KEY *pkey = (PKCS11_KEY *)vecdsa;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if (pkey == NULL)
        goto end;

    pkey->is_private = 0;
    ctx->pkey = pkey;
    ctx->type = CKM_ECDSA;
    ctx->isinit = 1;

    ret = pkcs11_open_session(ctx->pkcs11_ctx, &ctx->session);
    if (ret == 0)
        goto end;

end:
    if (ret == 0){
        if (ctx)
            pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    }
    return ret;
}

static int pkcs11_signature_verify(void *sigctx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    CK_MECHANISM mech = {0, NULL, 0};
    CK_RV rv = CKR_OK;
    CK_BYTE_PTR psig = (CK_BYTE_PTR)sig;
    CK_BYTE_PTR ptbs = (CK_BYTE_PTR)tbs;
    int ret = 0;

    if (!ctx)
        goto end;

    mech.mechanism = pkcs11_signature_get_mech_data(ctx, &mech);
    if (mech.mechanism == CKM_NULL)
        goto end;

    if (ctx->isinit) {
        CK_OBJECT_HANDLE keyhandle = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx->pkcs11_ctx,
                                                                                ctx->pkey,
                                                                                &ctx->session);

        if (keyhandle == CK_INVALID_HANDLE)
            goto end;

        /* Initialize with padding mode */
        rv = pkcs11_get_lib_functions()->C_VerifyInit(ctx->session,
                                                      &mech, keyhandle);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 0;
    }
    rv = pkcs11_get_lib_functions()->C_Verify(ctx->session,
                                              ptbs, tbslen, psig, siglen);
    if (rv != CKR_OK) {
        if (rv != CKR_SIGNATURE_INVALID)
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    ret = 1;
end:
    if (mech.pParameter != NULL)
        OPENSSL_free(mech.pParameter);

    return ret;
}

static void pkcs11_signature_freectx(void *sigctx)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;

    if (ctx != NULL) {
        pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
        OPENSSL_free(ctx);
    }
}

static void *pkcs11_signature_dupctx(void *sigctx)
{
    PKCS11_SIGN_CTX *source_ctx = (PKCS11_SIGN_CTX *)sigctx;
    PKCS11_SIGN_CTX *dest_ctx = NULL;

    if (source_ctx == NULL)
        goto end;
    if ((dest_ctx = OPENSSL_zalloc(sizeof(*dest_ctx))) == NULL) {
        OPENSSL_free(dest_ctx);
        return NULL;
    }
    dest_ctx->pkey = source_ctx->pkey;
    dest_ctx->type = source_ctx->type;
    dest_ctx->nid_md = source_ctx->nid_md;
    dest_ctx->nid_md_mgf1 = source_ctx->nid_md_mgf1;
    dest_ctx->pss_salt_len = source_ctx->pss_salt_len;
    dest_ctx->pkcs11_ctx = source_ctx->pkcs11_ctx;
    if (source_ctx->session != 0)
        pkcs11_open_session(dest_ctx->pkcs11_ctx, &dest_ctx->session);

end:
    return dest_ctx;
}

static unsigned char* pkcs11_rsa_signature_aid_gen(PKCS11_SIGN_CTX *ctx,
                                                   unsigned char *aid_buf,
                                                   size_t buf_len,
                                                   size_t *aid_len)
{
    WPACKET pkt;
    unsigned char *aid = NULL;
    int saltlen;
    RSA_PSS_PARAMS_30 pss_params;
    int ret;

    if (!WPACKET_init_der(&pkt, aid_buf, buf_len)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_CRYPTO_LIB);
        return NULL;
    }

    switch (ctx->type) {
    case CKM_RSA_PKCS:
        ret = ossl_DER_w_algorithmIdentifier_MDWithRSAEncryption(&pkt, -1,
                                                                 ctx->nid_md);

        if (ret > 0) {
            break;
        } else if (ret == 0) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }
        ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                       "Algorithm ID generation - md NID: %d",
                       ctx->nid_md);
        goto cleanup;
    case CKM_RSA_PKCS_PSS:
        saltlen = pkcs11_signature_get_mgf1_salt_len(ctx);
        if (saltlen < 0)
            goto cleanup;
        if (!ossl_rsa_pss_params_30_set_defaults(&pss_params)
            || !ossl_rsa_pss_params_30_set_hashalg(&pss_params, ctx->nid_md)
            || !ossl_rsa_pss_params_30_set_maskgenhashalg(&pss_params,
                                                          ctx->nid_md_mgf1)
            || !ossl_rsa_pss_params_30_set_saltlen(&pss_params, saltlen)
            || !ossl_DER_w_algorithmIdentifier_RSA_PSS(&pkt, -1,
                                                       RSA_FLAG_TYPE_RSASSAPSS,
                                                       &pss_params)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            goto cleanup;
        }
        break;
    default:
        goto cleanup;
    }
    if (WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, aid_len);
        aid = WPACKET_get_curr(&pkt);
    }
 cleanup:
    WPACKET_cleanup(&pkt);
    return aid;
}

static int pkcs11_signature_get_ctx_params(void *sigctx, OSSL_PARAM *params)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    OSSL_PARAM *p;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL) {
        /* The Algorithm Identifier of the combined signature algorithm */
        unsigned char aid_buf[128];
        unsigned char *aid;
        size_t  aid_len;

        aid = pkcs11_rsa_signature_aid_gen(ctx, aid_buf,
                                           sizeof(aid_buf), &aid_len);
        if (aid == NULL || !OSSL_PARAM_set_octet_string(p, aid, aid_len))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
    if (p != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_INTEGER:
            switch (ctx->type) {
            case CKM_RSA_PKCS:
                if (!OSSL_PARAM_set_int(p, RSA_PKCS1_PADDING))
                    goto end;
                break;
            case  CKM_RSA_PKCS_PSS:
                if (!OSSL_PARAM_set_int(p, RSA_PKCS1_PSS_PADDING))
                    goto end;
                break;
            default:
                goto end;
            }
            break;
        case OSSL_PARAM_UTF8_STRING:
            switch (ctx->type) {
            case CKM_RSA_PKCS:
                if (!OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PAD_MODE_PKCSV15))
                    goto end;
                break;
            case  CKM_RSA_PKCS_PSS:
                if (!OSSL_PARAM_set_utf8_string(p, OSSL_PKEY_RSA_PAD_MODE_PSS))
                    goto end;
                break;
            default:
                goto end;
            }
            break;
        default:
            goto end;
        }
    }
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL) {
        switch(p->data_type) {
        case OSSL_PARAM_UTF8_STRING: {
            const char *name = OBJ_nid2sn(ctx->nid_md);
            if (name == NULL)
                goto end;
            if (!OSSL_PARAM_set_utf8_string(p, name))
                goto end;
        }
        break;
        case OSSL_PARAM_INTEGER:
            if (!OSSL_PARAM_set_int(p, ctx->nid_md))
                goto end;
        break;
        default:
            goto end;
        }
    }
    ret = 1;
end:
    return ret;
}

static const OSSL_PARAM *pkcs11_signature_gettable_ctx_params(ossl_unused void *vprsactx,
                                                 ossl_unused void *provctx)
{
    return pkcs11_sign_gettable_ctx_params_tbl;
}

static int pkcs11_signature_set_ctx_params(void *sigctx, const OSSL_PARAM params[])
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    const OSSL_PARAM *p;
    char digestname[80];
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST)) != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_UTF8_STRING: {
            char *pdigestname = digestname;
            if (OSSL_PARAM_get_utf8_string(p, (char **)&pdigestname, sizeof(digestname))
                    != 1)
                goto end;
            /* Convert digest name into nid */
            if (strlen(digestname) <= 0 || strcmp(digestname, "UNDEF") == 0 ||
                    strcmp(digestname, "undefined") == 0)
                ctx->nid_md = NID_undef;
            else {
                /* Try short name first, then long name */
                ctx->nid_md = pkcs11_find_mdnid_by_name(digestname);
                if (ctx->nid_md == NID_undef)
                    goto end;
            }
        }
            break;
        case OSSL_PARAM_INTEGER: {
            int niddigest = -1;
            if (OSSL_PARAM_get_int(p, &niddigest) != 1)
                goto end;
            ctx->nid_md = niddigest;
        }
            break;
        }
    }

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST)) != NULL) {
        switch (p->data_type) {
        case OSSL_PARAM_UTF8_STRING: {
            char *pdigestname = digestname;
            if (OSSL_PARAM_get_utf8_string(p, (char **)&pdigestname, sizeof(digestname))
                    != 1)
                goto end;
            /* Convert digest name into nid */
            if (strlen(digestname) <= 0 || strcmp(digestname, "UNDEF") == 0 ||
                    strcmp(digestname, "undefined") == 0)
                ctx->nid_md_mgf1 = NID_undef;
            else {
                /* Try short name first, then long name */
                ctx->nid_md_mgf1 = pkcs11_find_mdnid_by_name(digestname);
                if (ctx->nid_md_mgf1 == NID_undef)
                    goto end;
            }
        }
            break;
        case OSSL_PARAM_INTEGER: {
            int niddigest = -1;
            if (OSSL_PARAM_get_int(p, &niddigest) != 1)
                goto end;
            ctx->nid_md_mgf1 = niddigest;
        }
            break;
        }
    }

    switch(ctx->type) {
        case CKM_RSA_PKCS:
        case  CKM_RSA_PKCS_PSS:
        {
            int val = 0;
            if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PAD_MODE)) != NULL) {
                switch(p->data_type) {
                case OSSL_PARAM_INTEGER:
                    if (OSSL_PARAM_get_int(p, &val) != 1)
                        goto end;
                    switch (val) {
                        case RSA_PKCS1_PADDING:
                            ctx->type = CKM_RSA_PKCS;
                        break;
                        case RSA_PKCS1_PSS_PADDING:
                            ctx->type = CKM_RSA_PKCS_PSS;
                        break;
                        default:
                            goto end;
                    }
                    break;
                case OSSL_PARAM_UTF8_STRING:
                {
                    char name[100];
                    char *pname = name;
                    if (OSSL_PARAM_get_utf8_string(p, &pname, sizeof(name)) != 1)
                        goto end;
                    if (strcmp(name, OSSL_PKEY_RSA_PAD_MODE_PKCSV15) == 0)
                        ctx->type = CKM_RSA_PKCS;
                    else if (strcmp(name, OSSL_PKEY_RSA_PAD_MODE_PSS) == 0)
                        ctx->type = CKM_RSA_PKCS_PSS;
                    else
                        goto end;
                    break;
                }}
            }
            if ((p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN)) != NULL) {
                switch (p->data_type) {
                    case OSSL_PARAM_INTEGER:
                        if (OSSL_PARAM_get_int(p, &val) != 1)
                            goto end;
                        break;
                    case OSSL_PARAM_UTF8_STRING: {
                        if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
                            val = RSA_PSS_SALTLEN_DIGEST;
                        else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
                            val = RSA_PSS_SALTLEN_MAX;
                        else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
                            val = RSA_PSS_SALTLEN_AUTO;
                        else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX) == 0)
                            val = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
                        else
                            val = atoi(p->data);
                        break;
                        default:
                            goto end;
                    }
                    break;
                }
                ctx->pss_salt_len = val;
            }
        }
        break;
    }

    ret = 1;
end:

    return ret;
}

static const OSSL_PARAM *pkcs11_signature_settable_ctx_params(ossl_unused void *vprsactx,
                                                 ossl_unused void *provctx)
{
    return pkcs11_sign_settable_ctx_params_tbl;
}

static int pkcs11_signature_digest_sign_verify_init(void *sigctx, const char *mdname,
                                                    void *keydata,
                                                    ossl_unused const OSSL_PARAM params[],
                                                    int verify)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    PKCS11_KEY *pkey = (PKCS11_KEY*)keydata;
    int ret = 0;

    if (!ctx)
        goto end;

    if (!ossl_prov_is_running())
        return 0;

    if (pkey == NULL)
        goto end;

    ctx->pkey = pkey;
    switch(pkey->type) {
        case CKK_RSA:
            if (ctx->type != CKM_RSA_PKCS_PSS)
                ctx->type = CKM_RSA_PKCS;
        break;
        case CKK_ECDSA:
            ctx->type = CKM_ECDSA;
        break;
    }

    ctx->pkey->is_private = (verify ? 0 : 1);
    ctx->isinit = 1;
    ctx->nid_md = pkcs11_find_mdnid_by_name(mdname);
    if (ctx->nid_md == NID_undef)
        goto end;
    ctx->nid_md_mgf1 = ctx->nid_md;

    ret = pkcs11_open_session(ctx->pkcs11_ctx, &ctx->session);
    if (ret == 0)
        goto end;

    ret = 1;
end:
    if (ret == 0) {
        if (ctx && ctx->pkcs11_ctx)
            pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    }
    return ret;
}

static int pkcs11_signature_digest_sign_verify_update(void *sigctx,
                                                      const unsigned char *data,
                                                      size_t datalen,
                                                      int verify)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    CK_RV rv = CKR_OK;
    CK_BYTE_PTR pdata = (CK_BYTE_PTR)data;
    int ret = 0;

    if (ctx->isinit) {
        CK_MECHANISM mech = {0, NULL, 0};
        CK_OBJECT_HANDLE keyhandle = CK_INVALID_HANDLE;

        keyhandle = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx->pkcs11_ctx, ctx->pkey,
                                                               &ctx->session);
        if (keyhandle == CK_INVALID_HANDLE)
            goto end;

        mech.mechanism = pkcs11_signature_get_mech_data(ctx, &mech);
        if (mech.mechanism == CKM_NULL)
            goto end;

        if (verify)
            rv = pkcs11_get_lib_functions()->C_VerifyInit(ctx->session,
                                                          &mech, keyhandle);
        else
            rv = pkcs11_get_lib_functions()->C_SignInit(ctx->session,
                                                          &mech, keyhandle);

        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 0;
    }

    if (verify)
        rv = pkcs11_get_lib_functions()->C_VerifyUpdate(ctx->session,
                                                        pdata, datalen);
    else
        rv = pkcs11_get_lib_functions()->C_SignUpdate(ctx->session,
                                                      pdata, datalen);

    if (rv != CKR_OK) {
        if (rv != CKR_SIGNATURE_INVALID)
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    ret = 1;
end:
    return ret;
}

static int pkcs11_signature_digest_sign_init(void *sigctx, const char *mdname,
                                void *keydata, const OSSL_PARAM params[])
{
    return pkcs11_signature_digest_sign_verify_init(sigctx, mdname, keydata, params, 0);
}

static int pksc11_signature_digest_sign(void *sigctx, unsigned char *sig,
                                        size_t *siglen, ossl_unused size_t sigsize,
                                        const unsigned char *tbs, size_t tbslen)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    PKCS11_KEY *pkey = NULL;
    CK_BYTE_PTR psig = (CK_BYTE_PTR)sig;
    CK_RV rv = CKR_OK;
    int ret = 0;

    if (!ctx)
        goto end;

    if (!ossl_prov_is_running())
        return 0;

    pkey = (PKCS11_KEY*)ctx->pkey;
    if (pkey == NULL)
        goto end;

    switch(pkey->type) {
        case CKK_RSA:
            if (ctx->type != CKM_RSA_PKCS_PSS)
                ctx->type = CKM_RSA_PKCS;
        break;
        case CKK_ECDSA:
            ctx->type = CKM_ECDSA;
        break;
    }

    if (ctx->nid_md == NID_undef)
        goto end;

    if (ctx->isinit) {
        CK_MECHANISM mech = {0, NULL, 0};
        CK_OBJECT_HANDLE keyhandle = CK_INVALID_HANDLE;

        keyhandle = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx->pkcs11_ctx, ctx->pkey,
                                                               &ctx->session);
        if (keyhandle == CK_INVALID_HANDLE)
            goto end;

        mech.mechanism = pkcs11_signature_get_mech_data(ctx, &mech);
        if (mech.mechanism == CKM_NULL)
            goto end;

        rv = pkcs11_get_lib_functions()->C_SignInit(ctx->session,
                                                    &mech, keyhandle);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 0;
    }

    if (psig == NULL) {
        ret = pkcs11_signature_required_length(ctx, siglen);
        goto end;
    }

    rv = pkcs11_get_lib_functions()->C_Sign(ctx->session,
                                            (CK_BYTE_PTR)tbs, tbslen,
                                            psig, siglen);
    if (rv != CKR_OK) {
        if (rv != CKR_SIGNATURE_INVALID)
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    ret = 1;
end:
    return ret;
}

static int pkcs11_signature_digest_sign_update(void *sigctx,
                                        const unsigned char *data,
                                        size_t datalen)
{
    return pkcs11_signature_digest_sign_verify_update(sigctx, data, datalen, 0);
}

static int pkcs11_signature_digest_sign_final(void *sigctx, unsigned char *sig,
                                 size_t *siglen, ossl_unused size_t sigsize)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    CK_RV rv = CKR_OK;
    CK_BYTE_PTR psig = (CK_BYTE_PTR)sig;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    if (psig == NULL) {
        ret = pkcs11_signature_required_length(ctx, siglen);
        goto end;
    }

    rv = pkcs11_get_lib_functions()->C_SignFinal(ctx->session,
                                                 psig, siglen);
    if (rv != CKR_OK) {
        if (rv != CKR_SIGNATURE_INVALID)
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    ret = 1;
end:
    return ret;
}

static int pkcs11_signature_digest_verify_init(void *sigctx, const char *mdname,
                                  void *keydata, const OSSL_PARAM params[])
{
    return pkcs11_signature_digest_sign_verify_init(sigctx, mdname, keydata, params, 1);
}

static int pkcs11_signature_digest_verify(void *sigctx, const unsigned char *sig,
                                          size_t siglen, const unsigned char *tbs,
                                          size_t tbslen)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    PKCS11_KEY *pkey = NULL;
    unsigned char *signature = NULL;
    CK_RV rv = CKR_OK;
    int ret = 0;

    if (!ctx)
        goto end;

    if (!ossl_prov_is_running())
        return 0;

    pkey = (PKCS11_KEY*)ctx->pkey;
    if (pkey == NULL)
        goto end;

    switch(pkey->type) {
        case CKK_RSA:
            if (ctx->type != CKM_RSA_PKCS_PSS)
                ctx->type = CKM_RSA_PKCS;
        break;
        case CKK_ECDSA: {
            ctx->type = CKM_ECDSA;
            STACK_OF(ASN1_TYPE) *intsk;
            unsigned char *p;
            int i, a = 0;
            int allen = 0;
            int order = 0;

            order = ctx->pkey->ecdsa.order;
            p = (unsigned char*)sig;
            intsk = d2i_ASN1_SEQUENCE_ANY(NULL, (const unsigned char**)&p, siglen);
            allen = sk_ASN1_TYPE_num(intsk) * order;
            signature = (unsigned char*)OPENSSL_zalloc(allen);
            p = signature;
            for (i = 0; i < sk_ASN1_TYPE_num(intsk); i++){
                ASN1_TYPE *item = sk_ASN1_TYPE_value(intsk, i);
                if (item) {
                    if (ASN1_TYPE_get(item) == V_ASN1_INTEGER) {
                        /* Add leading zeros */
                        for (a = 0; a < (order - item->value.integer->length); a++, p++)
                            *p = 0x00;
                        memcpy((unsigned char*)p, item->value.integer->data, item->value.integer->length);
                        p += item->value.integer->length;
                    }
                }
            }
            sk_ASN1_TYPE_pop_free(intsk, ASN1_TYPE_free);
            sig = signature;
            siglen = allen;
        }
        break;
    }

    if (ctx->nid_md == NID_undef)
        goto end;

    if (ctx->isinit) {
        CK_MECHANISM mech = {0, NULL, 0};
        CK_OBJECT_HANDLE keyhandle = CK_INVALID_HANDLE;

        keyhandle = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx->pkcs11_ctx, ctx->pkey,
                                                               &ctx->session);
        if (keyhandle == CK_INVALID_HANDLE)
            goto end;

        mech.mechanism = pkcs11_signature_get_mech_data(ctx, &mech);
        if (mech.mechanism == CKM_NULL)
            goto end;

        rv = pkcs11_get_lib_functions()->C_VerifyInit(ctx->session,
                                                      &mech, keyhandle);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end;
        }
        ctx->isinit = 0;
    }

    rv = pkcs11_get_lib_functions()->C_Verify(ctx->session,
                                              (CK_BYTE_PTR)tbs, tbslen,
                                              (CK_BYTE_PTR)sig, siglen);
    if (rv != CKR_OK) {
        if (rv != CKR_SIGNATURE_INVALID)
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    ret = 1;
end:
    if (signature)
        OPENSSL_free(signature);

    return ret;
}

static int pkcs11_signature_digest_verify_update(void *sigctx,
                                        const unsigned char *data,
                                        size_t datalen)
{
    return pkcs11_signature_digest_sign_verify_update(sigctx, data, datalen, 1);
}

static int pkcs11_signature_digest_verify_final(void *sigctx, const unsigned char *sig,
                            size_t siglen)
{
    PKCS11_SIGN_CTX *ctx = (PKCS11_SIGN_CTX *)sigctx;
    CK_RV rv = CKR_OK;
    CK_BYTE_PTR psig = (CK_BYTE_PTR)sig;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    rv = pkcs11_get_lib_functions()->C_VerifyFinal(ctx->session,
                                                   psig, siglen);
    if (rv != CKR_OK) {
        if (rv != CKR_SIGNATURE_INVALID)
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    ret = 1;
end:
    return ret;
}

OSSL_ALGORITHM *pkcs11_sign_get_algo_tbl(OPENSSL_STACK *sk, const char *id)
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
            case CKM_RSA_PKCS:
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_RSA, id,
                                     PKCS11_SIGNATURE_DB_TBL(rsa),
                                     PKCS11_SIGNATURE_ALGO_DESCR(rsa));
                break;
            case CKM_ECDSA:
#ifdef ENABLE_P11_EC
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_EC, id,
                                     PKCS11_SIGNATURE_DB_TBL(ecdsa),
                                     PKCS11_SIGNATURE_ALGO_DESCR(ecdsa));
#endif
                pkcs11_add_algorithm(algo_sk, PROV_NAMES_ECDSA, id,
                                     PKCS11_SIGNATURE_DB_TBL(ecdsa),
                                     PKCS11_SIGNATURE_ALGO_DESCR(ecdsa));
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

CK_ULONG pkcs11_signature_get_mgf1_salt_len(PKCS11_SIGN_CTX *ctx)
{
    CK_ULONG ret = 0;
    int saltlen = ctx->pss_salt_len;
    int saltlenMax = -1;
    const EVP_MD *md = NULL;

    md = EVP_get_digestbynid(ctx->nid_md);
    if (md == NULL)
        goto end;

    switch (ctx->pss_salt_len)
    {
    case RSA_PSS_SALTLEN_DIGEST:
        saltlen = EVP_MD_get_size(md);
        break;
    case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
        saltlen = RSA_PSS_SALTLEN_MAX;
        saltlenMax = EVP_MD_get_size(md);
        break;
    }
    if (saltlen == RSA_PSS_SALTLEN_MAX || saltlen == RSA_PSS_SALTLEN_AUTO) {
        saltlen = ctx->pkey->rsa.param_size - EVP_MD_get_size(md) - 2;
        if ((ctx->pkey->rsa.param_bits & 0x07) == 1)
            saltlen--;
        if (saltlenMax >= 0 && saltlen > saltlenMax)
            saltlen = saltlenMax;
    }
    if (saltlen > 0)
        ret = saltlen;
end:
    return ret;
}

CK_ULONG pkcs11_signature_get_mech_data(PKCS11_SIGN_CTX *ctx, CK_MECHANISM *mech)
{
    CK_RSA_PKCS_PSS_PARAMS *pss_param = NULL;
    int nid = ctx->nid_md;
    CK_ULONG type = ctx->type;
    CK_ULONG ret = CKM_NULL;

    switch (nid) {
        case NID_md5:
            switch(type) {
                case CKM_RSA_PKCS:
                    ret = CKM_MD5_RSA_PKCS;
                break;
            }
        break;
        case NID_sha1:
            switch(type) {
                case CKM_RSA_PKCS:
                    ret = CKM_SHA1_RSA_PKCS;
                break;
                case CKM_RSA_PKCS_PSS:
                    mech->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
                    pss_param = OPENSSL_zalloc(mech->ulParameterLen);
                    mech->pParameter = pss_param;
                    ret = CKM_SHA1_RSA_PKCS_PSS;
                break;
                case CKM_ECDSA:
                    ret = CKM_ECDSA_SHA1;
                break;
            }
        break;
        case NID_sha224:
            switch(type) {
                case CKM_RSA_PKCS:
                    ret = CKM_SHA224_RSA_PKCS;
                break;
                case CKM_RSA_PKCS_PSS:
                    mech->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
                    pss_param = OPENSSL_zalloc(mech->ulParameterLen);
                    mech->pParameter = pss_param;
                    ret = CKM_SHA224_RSA_PKCS_PSS;
                break;
                case CKM_ECDSA:
                    ret = CKM_ECDSA_SHA224;
                break;
            }
        break;
        case NID_sha256:
            switch(type) {
                case CKM_RSA_PKCS:
                    ret = CKM_SHA256_RSA_PKCS;
                break;
                case CKM_RSA_PKCS_PSS:
                    mech->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
                    pss_param = OPENSSL_zalloc(mech->ulParameterLen);
                    mech->pParameter = pss_param;
                    ret = CKM_SHA256_RSA_PKCS_PSS;
                break;
                case CKM_ECDSA:
                    ret = CKM_ECDSA_SHA256;
                break;
            }
        break;
        case NID_sha384:
            switch(type) {
                case CKM_RSA_PKCS:
                    ret = CKM_SHA384_RSA_PKCS;
                break;
                case CKM_RSA_PKCS_PSS:
                    mech->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
                    pss_param = OPENSSL_zalloc(mech->ulParameterLen);
                    mech->pParameter = pss_param;
                    ret= CKM_SHA384_RSA_PKCS_PSS;
                break;
                case CKM_ECDSA:
                    ret = CKM_ECDSA_SHA384;
                break;
            }
        break;
        case NID_sha512:
            switch(type) {
                case CKM_RSA_PKCS:
                    ret = CKM_SHA512_RSA_PKCS;
                break;
                case CKM_RSA_PKCS_PSS:
                    mech->ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);
                    pss_param = OPENSSL_zalloc(mech->ulParameterLen);
                    mech->pParameter = pss_param;
                    ret = CKM_SHA512_RSA_PKCS_PSS;
                break;
                case CKM_ECDSA:
                    ret = CKM_ECDSA_SHA512;
                break;
            }
        break;
    }
    if (pss_param) {
        pss_param->hashAlg = pkcs11_md_nid2ckm(ctx->nid_md);
        pss_param->mgf = pkcs11_md_nid2ckm_mgf1(ctx->nid_md_mgf1);
        pss_param->sLen = pkcs11_signature_get_mgf1_salt_len(ctx);
    }
    return ret;
}

static int pkcs11_signature_required_length(PKCS11_SIGN_CTX *ctx, size_t *len)
{
    if (ctx->type == CKM_RSA_PKCS || ctx->type == CKM_RSA_PKCS_PSS) {
        (*len) = BN_num_bytes(ctx->pkey->rsa.modulus);
        return 1;
    }
    else if (ctx->type == CKM_ECDSA) {
        int order = ctx->pkey->ecdsa.order;
        /* der sequence + tag + 2 x (integer tag  + size tag) */
        int der_overhead = 1 + 1 + 2 * (1 + 1);
        *len = der_overhead + 2 * order;
        return 1;
    }
    return 0;
}

