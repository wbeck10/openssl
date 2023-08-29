#include <stdlib.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/rsa.h>
#include <openssl/params.h>
#include <openssl/stack.h>
#include <openssl/objects.h>
#include <openssl/store.h>
#include <openssl/core_object.h>
#include <openssl/x509.h>
#include "prov/names.h"
#include "prov/providercommon.h"
#include "pkcs11_kmgmt.h"
#include "pkcs11_ctx.h"
#include "pkcs11_utils.h"
#include "../../include/crypto/evp.h"

#define PKCS11_X509_NAME_MAX (1024 * 1024)

/* Private functions */

#define PKCS11_STORE_ALGO_DESCRIPTION     "PKSC11 store"
static int pkcs11_store_get_cert_id(PKCS11_STORE_CTX *ctx, X509 *cert, char **id);

static char* pkcs11_store_description = PKCS11_STORE_ALGO_DESCRIPTION;

static OSSL_FUNC_store_open_fn                  pkcs11_store_open;
static OSSL_FUNC_store_attach_fn                pkcs11_store_attach;
static OSSL_FUNC_store_settable_ctx_params_fn   pkcs11_store_settable_ctx_params;
static OSSL_FUNC_store_set_ctx_params_fn        pkcs11_store_set_ctx_params;
static OSSL_FUNC_store_load_fn                  pkcs11_store_load;
static OSSL_FUNC_store_eof_fn                   pkcs11_store_eof;
static OSSL_FUNC_store_close_fn                 pkcs11_store_close;
static OSSL_FUNC_store_add_fn                   pkcs11_store_add;


const OSSL_DISPATCH pkcs11_store_functions[] = {
    { OSSL_FUNC_STORE_OPEN,     (void (*)(void))pkcs11_store_open },
    { OSSL_FUNC_STORE_ATTACH,   (void (*)(void))pkcs11_store_attach },
    { OSSL_FUNC_STORE_SETTABLE_CTX_PARAMS,
                                (void (*)(void))pkcs11_store_settable_ctx_params },
    { OSSL_FUNC_STORE_SET_CTX_PARAMS,
                                (void (*)(void))pkcs11_store_set_ctx_params },
    { OSSL_FUNC_STORE_LOAD,     (void (*)(void))pkcs11_store_load },
    { OSSL_FUNC_STORE_EOF,      (void (*)(void))pkcs11_store_eof },
    { OSSL_FUNC_STORE_CLOSE,    (void (*)(void))pkcs11_store_close },
    { OSSL_FUNC_STORE_ADD,      (void (*)(void))pkcs11_store_add },
    { 0, NULL },
};

static const OSSL_PARAM pkcs11_store_settable_ctx_params_tbl[] = {
    OSSL_PARAM_int(OSSL_STORE_PARAM_EXPECT, NULL),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_SUBJECT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_ISSUER, NULL, 0),
    OSSL_PARAM_int(OSSL_STORE_PARAM_SERIAL, NULL),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_FINGERPRINT, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_ALIAS, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_STORE_PARAM_KEY_ALIAS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_CERT, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_STORE_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static void *pkcs11_store_open(void *provctx, const char *uri)
{
    PKCS11_CTX *pctx = (PKCS11_CTX *)provctx;
    PKCS11_STORE_CTX* ctx = NULL;
    PKCS11_STORE_CTX* ret = NULL;

    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        SET_PKCS11_PROV_ERR(pctx, ERR_PKCS11_MEM_ALLOC_FAILED);
        OPENSSL_free(ctx);
        return NULL;
    }
    ctx->pkcs11_ctx = pctx;
    if (pkcs11_open_session(ctx->pkcs11_ctx, &ctx->session) == 0)
        goto end;

    ret = ctx;

end:
    if (ret == NULL) {
        if (ctx)
            pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
    }
    return ret;
}

int pkcs11_store_add_pkey(PKCS11_STORE_CTX *ctx, EVP_PKEY *pkey, char *label, int label_len,
                          unsigned char *id, int id_len)
{
    int ret = 0;
    PKCS11_KEY *key = NULL;
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;

    if (pkey == NULL)
        goto end;

    key = (PKCS11_KEY*)pkey->keydata;

    /* Key is already added in import.
     * We just need to add the label and id.
     */
    handle = pkcs11_keymgmt_get_keyhandle_from_keyparam(ctx->pkcs11_ctx, key, &ctx->session);
    if (handle == CK_INVALID_HANDLE)
        goto end;

    ret = pkcs11_keymgmt_update_key(ctx->pkcs11_ctx, key, handle, ctx->session,
                              label, label_len, id, id_len);
end:
    return ret;
}

int pkcs11_store_add_cert(PKCS11_STORE_CTX *ctx, X509 *cert, char *label, int label_len,
                          unsigned char *id, int id_len)
{
    int ret = 0;
    unsigned char* pder = NULL;
    int der_len = 0;
    unsigned char *p = NULL;
    X509_NAME *subject_name = NULL;
    X509_NAME *issuer_name = NULL;
    ASN1_INTEGER *serial = NULL;
    CK_RV rc = CKR_CANCEL;
    CK_OBJECT_HANDLE hCert;
    CK_BYTE is_true = TRUE;
    CK_BYTE is_false = FALSE;
    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_ATTRIBUTE cert_attribs[] = {
        {CKA_CLASS, &cert_class, sizeof(cert_class)},
        {CKA_TOKEN, &is_true, sizeof(is_true)},
        {CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type)},
        {CKA_PRIVATE, &is_false, sizeof(is_false)},
        {CKA_MODIFIABLE, &is_true, sizeof(is_true)},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0},
        {0, NULL, 0}};
    int alloc_item_start_idx = 5;
    int idx = alloc_item_start_idx;
    unsigned char buf[PKCS11_X509_NAME_MAX];
    int buflen = sizeof(buf);

    if (cert == NULL)
        goto end;

    der_len = i2d_X509(cert, NULL);
    if (der_len <= 0)
        goto end;

    pder = (unsigned char*)OPENSSL_zalloc(der_len);
    if (pder == NULL)
        goto end;

    p = pder;
    der_len = i2d_X509(cert, &p);
    if (der_len <= 0)
        goto end;

    subject_name = X509_get_subject_name(cert);
    issuer_name = X509_get_issuer_name(cert);
    serial = X509_get_serialNumber(cert);

    /* Setup label */
    if (label != NULL && label_len > 0) {
        cert_attribs[idx].type = CKA_LABEL;
        cert_attribs[idx].pValue = label;
        cert_attribs[idx].ulValueLen = label_len;
        idx++;
        alloc_item_start_idx++;
    }

    /* Setup ID */
    if (id != NULL && id_len > 0) {
        cert_attribs[idx].type = CKA_ID;
        cert_attribs[idx].pValue = id;
        cert_attribs[idx].ulValueLen = id_len;
        idx++;
        alloc_item_start_idx++;
    }

    /* Setup value */
    cert_attribs[idx].type = CKA_VALUE;
    cert_attribs[idx].pValue = pder;
    cert_attribs[idx].ulValueLen = der_len;
    idx++;
    alloc_item_start_idx++;

    /* Setup subject name */
    p = buf;
    buflen = i2d_X509_NAME(subject_name, (unsigned char**)&p);
    cert_attribs[idx].type = CKA_SUBJECT;
    cert_attribs[idx].ulValueLen = buflen;
    cert_attribs[idx].pValue = OPENSSL_zalloc(cert_attribs[idx].ulValueLen);
    memcpy(cert_attribs[idx].pValue, buf, buflen);
    idx++;

    /* Setup issuer name */
    p = buf;
    if (issuer_name != NULL) {
        buflen = i2d_X509_NAME(issuer_name, (unsigned char**)&p);
        cert_attribs[idx].type = CKA_ISSUER;
        cert_attribs[idx].ulValueLen = buflen;
        cert_attribs[idx].pValue = OPENSSL_zalloc(cert_attribs[idx].ulValueLen);
        memcpy(cert_attribs[idx].pValue, buf, buflen);
        idx++;
    }

    /* Setup serial number */
    p = buf;
    if (serial != NULL) {
        buflen = i2d_ASN1_INTEGER(serial, (unsigned char**)&p);
        cert_attribs[idx].type = CKA_SERIAL_NUMBER;
        cert_attribs[idx].ulValueLen = buflen;
        cert_attribs[idx].pValue = OPENSSL_zalloc(cert_attribs[idx].ulValueLen);
        memcpy(cert_attribs[idx].pValue, buf, buflen);
        idx++;
    }

    rc = pkcs11_get_lib_functions()->C_CreateObject(ctx->session, cert_attribs,
                                                    idx, &hCert);
    if (rc != CKR_OK)
        goto end;

    ret = 1;
end:
    for (idx--; idx >= alloc_item_start_idx; idx--) {
        if (cert_attribs[idx].pValue)
            OPENSSL_free(cert_attribs[idx].pValue);
    }
    if (pder)
        OPENSSL_free(pder);

    return ret;
}

int pkcs11_store_add(void *loaderctx, OSSL_STORE_INFO *info, const OSSL_PARAM params[])
{
    PKCS11_STORE_CTX *ctx = (PKCS11_STORE_CTX *)loaderctx;
    int ret = 0;
    const OSSL_PARAM *p = NULL;
    char *p_alias = NULL;
    int alias_len = 0;
    unsigned char *p_id = NULL;
    int id_len = 0;

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ALIAS);
    if (p != NULL) {
        if (!OSSL_PARAM_get_utf8_string_ptr(p, (const char **)&p_alias))
            goto end;
        alias_len = strlen(p_alias);
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ID);
    if (p != NULL) {
        if (!OSSL_PARAM_get_utf8_string_ptr(p, (const char **)&p_id))
            goto end;
        id_len = strlen((char*)p_id);
    }

    switch(OSSL_STORE_INFO_get_type(info)) {
    case OSSL_STORE_INFO_CERT:
        ret = pkcs11_store_add_cert(ctx, OSSL_STORE_INFO_get0_CERT(info),
                                    p_alias, alias_len, p_id, id_len);
        break;
    case OSSL_STORE_INFO_PUBKEY:
        ret = pkcs11_store_add_pkey(ctx, OSSL_STORE_INFO_get0_PUBKEY(info),
                                    p_alias, alias_len, p_id, id_len);
        break;
    case OSSL_STORE_INFO_PKEY:
        ret = pkcs11_store_add_pkey(ctx, OSSL_STORE_INFO_get0_PKEY(info),
                                    p_alias, alias_len, p_id, id_len);
        break;
    }

end:
    return ret;
}

void *pkcs11_store_attach(ossl_unused void *provctx, ossl_unused OSSL_CORE_BIO *cin)
{
    return NULL;
}

static const OSSL_PARAM *pkcs11_store_settable_ctx_params(ossl_unused void *provctx)
{
    return pkcs11_store_settable_ctx_params_tbl;
}

static int pkcs11_store_set_ctx_params(void *loaderctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    PKCS11_STORE_CTX *ctx = (PKCS11_STORE_CTX *)loaderctx;
    int ret = 0;

    if (ctx == NULL)
        goto end;

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
    if (p != NULL && !OSSL_PARAM_get_int(p, &ctx->expected_type))
        goto end;
    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SUBJECT);
    if (p != NULL) {
        const unsigned char *der = NULL;
        size_t der_len = 0;

        if (ctx->search_filter.x509_subject)
            X509_NAME_free(ctx->search_filter.x509_subject);
        ctx->search_filter.x509_subject = NULL;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&der, &der_len)
            || (ctx->search_filter.x509_subject =
                d2i_X509_NAME(NULL, &der, der_len)) == NULL)
            goto end;
        ctx->search_filter.search_flag |= PKCS11_SEARCH_NAME_SUBJECT;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ISSUER);
    if (p != NULL) {
        const unsigned char *der = NULL;
        size_t der_len = 0;

        if (ctx->search_filter.x509_issuer)
            X509_NAME_free(ctx->search_filter.x509_issuer);
        ctx->search_filter.x509_issuer = NULL;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&der, &der_len)
            || (ctx->search_filter.x509_issuer =
                d2i_X509_NAME(NULL, &der, der_len)) == NULL)
            goto end;
        ctx->search_filter.search_flag |= PKCS11_SEARCH_NAME_ISSUER;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_ALIAS);
    if (p != NULL) {
        char *palias;
        int alias_len = 0;
        if (ctx->search_filter.alias)
            OPENSSL_free(ctx->search_filter.alias);
        if (!OSSL_PARAM_get_utf8_string_ptr(p, (const char **)&palias))
            goto end;
        alias_len = strlen(palias);
        ctx->search_filter.alias = OPENSSL_zalloc(alias_len + 1);
        memcpy(ctx->search_filter.alias, palias, alias_len);
        ctx->search_filter.search_flag |= PKCS11_SEARCH_NAME_ALIAS;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_SERIAL);
    if (p != NULL) {
        if (!OSSL_PARAM_get_BN(p, &ctx->search_filter.serial))
            goto end;
        ctx->search_filter.search_flag |= PKCS11_SEARCH_SERIAL;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_KEY_ALIAS);
    if (p != NULL) {
        char *palias;
        int alias_len = 0;
        if (ctx->search_filter.key_alias)
            OPENSSL_free(ctx->search_filter.key_alias);
        if (!OSSL_PARAM_get_utf8_string_ptr(p, (const char **)&palias))
            goto end;
        alias_len = strlen(palias);
        ctx->search_filter.key_alias = OPENSSL_zalloc(alias_len + 1);
        memcpy(ctx->search_filter.key_alias, palias, alias_len);
        ctx->search_filter.search_flag |= PKCS11_SEARCH_KEY_ALIAS;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_CERT);
    if (p != NULL) {
        size_t len = sizeof(X509 *);
        if (ctx->search_filter.cert != NULL)
            X509_free(ctx->search_filter.cert);
        ctx->search_filter.cert = NULL;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&ctx->search_filter.cert, &len))
            goto end;
        X509_up_ref(ctx->search_filter.cert);
        ctx->search_filter.search_flag |= PKCS11_SEARCH_PRIV_KEY_WITH_CERT;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_PUB_KEY);
    if (p != NULL) {
        size_t len = sizeof(EVP_PKEY*);
        if (ctx->search_filter.pubkey != NULL)
            EVP_PKEY_free(ctx->search_filter.pubkey);
        ctx->search_filter.pubkey = NULL;
        if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&ctx->search_filter.pubkey, &len))
            goto end;
        EVP_PKEY_up_ref(ctx->search_filter.pubkey);
        ctx->search_filter.search_flag |= PKCS11_SEARCH_PRIV_KEY_WITH_PUB_KEY;
    }
    ret = 1;
end:

    return ret;
}

static int pkcs11_store_get_cert_id(PKCS11_STORE_CTX *ctx, X509 *cert, char **id)
{
    int ret = 0;
    CK_RV rv = CKR_CANCEL;
    CK_BBOOL flag_token = CK_TRUE;
    CK_OBJECT_CLASS obj_class = CKO_CERTIFICATE;
    CK_ATTRIBUTE find_attribs[] = {
        {CKA_TOKEN, &flag_token, sizeof(flag_token)},
        {CKA_CLASS, &obj_class, sizeof(obj_class)}
    };
    CK_OBJECT_HANDLE objs[MAX_STORE_OBJ_COUNT];
    CK_ULONG objs_len = 0;
    int i = 0;
    const ASN1_INTEGER *serial_cert = NULL;
    CK_ATTRIBUTE cert_attribs[] = {
        {CKA_ID, NULL, 0},
        {CKA_VALUE, NULL, 0}};
    int found = 0;
    unsigned long subj_hash = X509_subject_name_hash(cert);
    unsigned long issuer_hash = X509_issuer_name_hash(cert);

    /* Get a list of all the certificates */
    rv = pkcs11_get_lib_functions()->C_FindObjectsInit(ctx->session,
                                                       find_attribs,
                                                       (sizeof(find_attribs) / sizeof(CK_ATTRIBUTE)));
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    rv = pkcs11_get_lib_functions()->C_FindObjects(ctx->session,
                                                   objs, MAX_STORE_OBJ_COUNT,
                                                   &objs_len);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    rv = pkcs11_get_lib_functions()->C_FindObjectsFinal(ctx->session);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    /* Find the certificate matching the serial number */
    serial_cert = X509_get0_serialNumber(cert);
    for (i = 0; i < (int)objs_len && !found; i++) {
        X509 *icert = NULL;
        unsigned char* der = NULL;
        size_t der_len = 0;
        rv = pkcs11_get_lib_functions()->C_GetAttributeValue(ctx->session,
                                                             objs[i],
                                                             cert_attribs,
                                                             (sizeof(cert_attribs) / sizeof(CK_ATTRIBUTE)));
        if (rv != CKR_OK)
            goto end;

        /* Allocate memory for the attributes */
        if (cert_attribs[0].ulValueLen == 0)
            continue;
        cert_attribs[0].pValue = OPENSSL_zalloc(cert_attribs[0].ulValueLen);
        der_len = cert_attribs[1].ulValueLen;
        der = OPENSSL_zalloc(cert_attribs[1].ulValueLen);
        cert_attribs[1].pValue = der;
        rv = pkcs11_get_lib_functions()->C_GetAttributeValue(ctx->session,
                                                             objs[i],
                                                             cert_attribs,
                                                             (sizeof(cert_attribs) / sizeof(CK_ATTRIBUTE)));
        if (rv == CKR_OK) {
            unsigned char *pder = der;
            if (d2i_X509(&icert, (const unsigned char **)&pder,
                    der_len) != NULL) {
                const ASN1_INTEGER* serial_icert = NULL;
                serial_icert = X509_get0_serialNumber(icert);
                if (ASN1_INTEGER_cmp(serial_cert, serial_icert) == 0) {
                    unsigned isubj_hash = X509_subject_name_hash(icert);
                    if (isubj_hash == subj_hash) {
                        unsigned long iissuer_hash = X509_issuer_name_hash(icert);
                        if (iissuer_hash == issuer_hash) {
                            *id = OPENSSL_zalloc(cert_attribs[0].ulValueLen + 1);
                            memcpy(*id, cert_attribs[0].pValue, cert_attribs[0].ulValueLen);
                            ret = cert_attribs[0].ulValueLen;
                            found = 1;
                        }
                    }
                }
                X509_free(icert);
            }
        }
        OPENSSL_free(der);
        OPENSSL_free(cert_attribs[0].pValue);
    }
end:
    return ret;
}

char* pkcs11_store_get_ec_param(PKCS11_STORE_CTX *ctx, EVP_PKEY *eckey)
{
    char* ret = NULL;
    CK_RV rv = CKR_CANCEL;
    CK_BBOOL is_true = CK_TRUE;
    CK_OBJECT_CLASS obj_class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE find_privkey[] = {
        {CKA_TOKEN, &is_true, sizeof(is_true)},
        {CKA_CLASS, &obj_class, sizeof(obj_class)},
        {CKA_PRIVATE, &is_true, sizeof(is_true)},
    };
    CK_OBJECT_HANDLE objs[MAX_STORE_OBJ_COUNT];
    CK_ULONG objs_len = 0;
    int i = 0;
    int found = 0;

    /* Get a list of all the private keys */
    rv = pkcs11_get_lib_functions()->C_FindObjectsInit(ctx->session,
                                                       find_privkey,
                                                       (sizeof(find_privkey) / sizeof(CK_ATTRIBUTE)));
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }
    rv = pkcs11_get_lib_functions()->C_FindObjects(ctx->session,
                                                   objs, MAX_STORE_OBJ_COUNT,
                                                   &objs_len);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }

    rv = pkcs11_get_lib_functions()->C_FindObjectsFinal(ctx->session);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
        goto end;
    }


    /* Find the private matching the parameters */
    for (i = 0; i < (int)objs_len && !found; i++) {
    }

end:
    return ret;
}

int pkcs11_store_get_find_attributes(PKCS11_STORE_CTX *ctx,
                                     CK_ATTRIBUTE *attributes,
                                     int *startidx)
{
    int i = 0;
    unsigned char *p = NULL;
    CK_ATTRIBUTE* find_attribs = attributes;
    int ret = 0;

    /* Go to the attribute which is free to used */
    for (i = 0; i < (*startidx); i++)
        find_attribs++;

    if (ctx->search_filter.search_flag & PKCS11_SEARCH_PRIV_KEY_WITH_CERT) {
        char *certid;
        int certid_len = 0;

        if (ctx->search_filter.cert == NULL)
            goto end;

        certid_len = pkcs11_store_get_cert_id(ctx, ctx->search_filter.cert, &certid);
        if (certid == NULL || certid_len <= 0)
            goto end;
        find_attribs->type = CKA_ID;
        find_attribs->ulValueLen = certid_len;
        find_attribs->pValue = certid;
        find_attribs++;
        (*startidx)++;
        find_attribs->type = CKA_CLASS;
        find_attribs->pValue = OPENSSL_zalloc(sizeof(CK_OBJECT_CLASS));
        (*(CK_OBJECT_CLASS*)find_attribs->pValue) = CKO_PRIVATE_KEY;
        find_attribs->ulValueLen = sizeof(CK_OBJECT_CLASS);
        find_attribs++;
        (*startidx)++;
    }

    if (ctx->search_filter.search_flag & PKCS11_SEARCH_NAME_SUBJECT &&
            ctx->search_filter.x509_subject) {
        find_attribs->ulValueLen = i2d_X509_NAME(ctx->search_filter.x509_subject, NULL);
        if (find_attribs->ulValueLen > 0) {
            find_attribs->pValue =
                    OPENSSL_zalloc(find_attribs->ulValueLen);
            p = find_attribs->pValue;
            find_attribs->type = CKA_SUBJECT;
            find_attribs->ulValueLen = i2d_X509_NAME(ctx->search_filter.x509_subject,
                                                     &p);
            find_attribs++;
            (*startidx)++;
        }
    }

    if (ctx->search_filter.search_flag & PKCS11_SEARCH_NAME_ISSUER &&
            ctx->search_filter.x509_issuer) {
        find_attribs->ulValueLen = i2d_X509_NAME(ctx->search_filter.x509_issuer, NULL);
        if (find_attribs->ulValueLen > 0) {
            find_attribs->pValue =
                    OPENSSL_zalloc(find_attribs->ulValueLen);
            p = find_attribs->pValue;
            find_attribs->type = CKA_SUBJECT;
            find_attribs->ulValueLen = i2d_X509_NAME(ctx->search_filter.x509_issuer,
                                                     &p);
            find_attribs++;
            (*startidx)++;
        }
    }

    if (ctx->search_filter.search_flag & PKCS11_SEARCH_NAME_ALIAS &&
            ctx->search_filter.alias) {
        find_attribs->type = CKA_LABEL;
        /* Add '\0' as well to attribute length otherwise there is no match */
        find_attribs->ulValueLen = strlen(ctx->search_filter.alias);
        find_attribs->pValue =
                OPENSSL_zalloc(find_attribs->ulValueLen);
        memcpy(find_attribs->pValue, ctx->search_filter.alias,
               find_attribs->ulValueLen);
        find_attribs++;
        (*startidx)++;
    }

    if (ctx->search_filter.search_flag & PKCS11_SEARCH_SERIAL &&
            ctx->search_filter.serial) {
        ASN1_INTEGER *asn1_int = NULL;
        asn1_int = BN_to_ASN1_INTEGER(ctx->search_filter.serial, asn1_int);
        if (asn1_int != NULL) {
            find_attribs->type = CKA_SERIAL_NUMBER;
            find_attribs->ulValueLen = i2d_ASN1_INTEGER(asn1_int, NULL);
            find_attribs->pValue =
                    OPENSSL_zalloc(find_attribs->ulValueLen);
            p = find_attribs->pValue;
            find_attribs->ulValueLen = i2d_ASN1_INTEGER(asn1_int, &p);
            find_attribs++;
            (*startidx)++;
            ASN1_INTEGER_free(asn1_int);
        }
    }

    if (ctx->search_filter.search_flag & PKCS11_SEARCH_KEY_ALIAS &&
            ctx->search_filter.key_alias) {
        find_attribs->type = CKA_LABEL;
        find_attribs->ulValueLen = strlen((char*)ctx->search_filter.key_alias);
        find_attribs->pValue =
                OPENSSL_zalloc(find_attribs->ulValueLen);
        memcpy(find_attribs->pValue, ctx->search_filter.key_alias,
               find_attribs->ulValueLen);
        find_attribs++;
        (*startidx)++;
    }

    if ((ctx->search_filter.search_flag &
            PKCS11_SEARCH_PRIV_KEY_WITH_PUB_KEY) &&
            ctx->search_filter.pubkey) {
        int keytype = EVP_PKEY_get_id(ctx->search_filter.pubkey);
        if (keytype == EVP_PKEY_RSA || keytype == EVP_PKEY_RSA2) {
            BIGNUM *n_out = NULL;
/*            BIGNUM *e_out = NULL;*/
            CK_BBOOL is_private = CK_TRUE;
            find_attribs->type = CKA_PRIVATE;
            find_attribs->ulValueLen = sizeof(is_private);
            find_attribs->pValue =
                    OPENSSL_zalloc(find_attribs->ulValueLen);
            memcpy(find_attribs->pValue, &is_private,
                   find_attribs->ulValueLen);
            find_attribs++;
            (*startidx)++;

            /* Modulus */
            if (EVP_PKEY_get_bn_param(ctx->search_filter.pubkey,
                                      OSSL_PKEY_PARAM_RSA_N, &n_out)) {
                find_attribs->ulValueLen = BN_num_bytes(n_out);
                if (find_attribs->ulValueLen > 0) {
                    find_attribs->pValue = OPENSSL_zalloc(
                                find_attribs->ulValueLen);
                    BN_bn2bin(n_out, find_attribs->pValue);
                    find_attribs->type = CKA_MODULUS;
                }
                BN_free(n_out);
                find_attribs++;
                (*startidx)++;
            }

            /* Public Exponent */
/*            if (EVP_PKEY_get_bn_param(ctx->search_filter.pubkey,
                                          OSSL_PKEY_PARAM_RSA_E, &e_out)) {
                find_attribs->ulValueLen = BN_num_bytes(e_out);
                if (find_attribs->ulValueLen > 0) {
                    find_attribs->pValue = OPENSSL_zalloc(
                                find_attribs->ulValueLen);
                    BN_bn2bin(e_out, find_attribs->pValue);
                    find_attribs->type = CKA_PUBLIC_EXPONENT;
                }
                BN_free(e_out);
                find_attribs++;
                (*startidx)++;
            }*/
        }
        if (keytype == EVP_PKEY_EC) {
            pkcs11_store_get_ec_param(ctx, ctx->search_filter.pubkey);
        }
    }
    ret = 1;
end:
    return ret;
}

static int pkcs11_store_load(void *loaderctx,
                     OSSL_CALLBACK *object_cb, void *object_cbarg,
                     ossl_unused OSSL_PASSPHRASE_CALLBACK *pw_cb, ossl_unused void *pw_cbarg)
{
    PKCS11_STORE_CTX* ctx = (PKCS11_STORE_CTX *)loaderctx;
    CK_RV rv = CKR_OK;
    int ret = 1;

    if (ctx == NULL)
        goto end;

    /* Get list of object in store */
    if (!ctx->loaded) {
        ctx->seek = 0;
        CK_BBOOL flag_token = CK_TRUE;
        CK_ATTRIBUTE find_attribs[] = {
            {CKA_TOKEN, &flag_token, sizeof(flag_token)},
            {0, NULL, 0},
            {0, NULL, 0},
            {0, NULL, 0},
            {0, NULL, 0},
            {0, NULL, 0},
            {0, NULL, 0},
            {0, NULL, 0},
            {0, NULL, 0},
            {0, NULL, 0}
        };
        int attr_idx = 1;
        if (pkcs11_store_get_find_attributes(ctx, find_attribs, &attr_idx) == 0) {
            rv = CKR_CANCEL;
            goto end_find;
        }

        rv = pkcs11_get_lib_functions()->C_FindObjectsInit(ctx->session, find_attribs, attr_idx);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end_find;
        }
        rv = pkcs11_get_lib_functions()->C_FindObjects(ctx->session,
                                                       ctx->obj_list, MAX_STORE_OBJ_COUNT,
                                                       &ctx->count);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end_find;
        }

        rv = pkcs11_get_lib_functions()->C_FindObjectsFinal(ctx->session);
        if (rv != CKR_OK) {
            SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
            goto end_find;
        }
end_find:
        /* Free search attributes memory */
        for (attr_idx--; attr_idx > 0; attr_idx--) {
            if (find_attribs[attr_idx].pValue)
                OPENSSL_free(find_attribs[attr_idx].pValue);
        }
        if (rv != CKR_OK)
            goto end;

        {
            CK_ULONG i = 0;
            /* Iterate over all object handles and querry the metadatas */
            for (i = 0; i < ctx->count; i++) {
                /* Find out the class type of this object */
                CK_OBJECT_CLASS obj_class = CKO_SECRET_KEY;
                CK_ATTRIBUTE obj_attr[] = {
                    {CKA_CLASS, &obj_class, sizeof(obj_class)}
                };
                ctx->items[i].obj_handle = ctx->obj_list[i];
                ctx->items[i].pkcs11_ctx = ctx->pkcs11_ctx;
                ctx->items[i].obj_class = CK_UNAVAILABLE_INFORMATION;
                ctx->items[i].session = ctx->session;
                rv = pkcs11_get_lib_functions()->C_GetAttributeValue(ctx->session,
                                                                     ctx->obj_list[i], obj_attr,
                                                                     1);
                if (rv != CKR_OK) {
                    SET_PKCS11_PROV_ERR(ctx->pkcs11_ctx, rv);
                    goto end;
                }
                ctx->items[i].obj_class = obj_class;
                ctx->items[i].obj_keytype = CK_UNAVAILABLE_INFORMATION;
                switch (obj_class) {
                case CKO_PRIVATE_KEY:
                case CKO_PUBLIC_KEY:
                case CKO_SECRET_KEY:
                {
                    /* If the object is a key then we need to get the key type */
                    CK_KEY_TYPE key_type = CKK_DES;
                    CK_ATTRIBUTE keytype_attr[] = {
                        {CKA_KEY_TYPE, &key_type, sizeof(key_type)}
                    };
                    rv = pkcs11_get_lib_functions()->C_GetAttributeValue(ctx->session,
                                                                         ctx->obj_list[i], keytype_attr,
                                                                         1);
                    if (rv == CKR_OK) {
                        ctx->items[i].obj_keytype = key_type;
                    }
                }
                    break;
                case CKO_CERTIFICATE:
                    break;
                default:
                    break;
                }
            }
        }
        ctx->loaded = 1;
    }

    /* The store is loaded */
    if (ctx->count > ctx->seek) {
        OSSL_PARAM params[5];
        char* osl_type = NULL;
        int osl_class = 0;
        char ispkey = 0;
        char iscert = 0;
        int i = 0;
        CK_ATTRIBUTE cert_attribs[] = {
            {CKA_VALUE, NULL, 0}};

        switch (ctx->items[ctx->seek].obj_class) {
        case CKO_PUBLIC_KEY:
        case CKO_PRIVATE_KEY:
            osl_class = OSSL_OBJECT_PKEY;
            ispkey = 1;
            break;
        case CKO_SECRET_KEY:
            break;
        case CKO_DATA:
            break;
        case CKO_CERTIFICATE:
            /* There is no specific object type for PKCS12 */
            osl_class = OSSL_OBJECT_CERT;
            osl_type = PEM_STRING_X509_TRUSTED;
            iscert = 1;
            break;
        }
        if (ispkey) {
            osl_class = OSSL_OBJECT_PKEY;
            switch (ctx->items[ctx->seek].obj_keytype) {
            case CKK_RSA:
                osl_type = "RSA";
                break;
            case CKK_ECDSA:
                osl_type = "EC";
                break;
            default:
                break;
            }
        }
        params[i++] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &osl_class);
        params[i++] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                     osl_type, 0);

        /* giving away the object by reference */
        params[i++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
                                                      &ctx->items[ctx->seek],
                                                      sizeof(PKCS11_STORE_OBJ));
        if (iscert) {
            int attributes_len = sizeof (cert_attribs) / sizeof (CK_ATTRIBUTE);
            rv = pkcs11_get_lib_functions()->C_GetAttributeValue(ctx->session,
                                                                 ctx->items[ctx->seek].obj_handle,
                                                                 cert_attribs,
                                                                 attributes_len);
            if (rv != CKR_OK)
                goto end;

            /* Allocate memory for the attributes */
            cert_attribs[0].pValue = OPENSSL_zalloc(cert_attribs[0].ulValueLen);
            rv = pkcs11_get_lib_functions()->C_GetAttributeValue(ctx->session,
                                                                 ctx->items[ctx->seek].obj_handle,
                                                                 cert_attribs,
                                                                 attributes_len);
            if (rv != CKR_OK)
                goto end;

            params[i++] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                              cert_attribs[0].pValue,
                                              cert_attribs[0].ulValueLen);
        }
        params[i++] = OSSL_PARAM_construct_end();
        ctx->seek++;
        ret = object_cb(params, object_cbarg);
        if (cert_attribs[0].pValue)
            OPENSSL_free(cert_attribs[0].pValue);
    }
end:
    return ret;
}

static int pkcs11_store_eof(void *loaderctx)
{
    PKCS11_STORE_CTX* ctx = (PKCS11_STORE_CTX *)loaderctx;
    if (ctx == NULL)
        goto end;
    if (!ctx->loaded)
        return 0;
    if ((ctx->seek) >= ctx->count)
        return 1;
end:
    return 0;
}

static int pkcs11_store_close(void *loaderctx)
{
    PKCS11_STORE_CTX* ctx = (PKCS11_STORE_CTX *)loaderctx;
    if (ctx != NULL) {
        if (ctx->search_filter.x509_subject)
            X509_NAME_free(ctx->search_filter.x509_subject);
        ctx->search_filter.x509_subject = NULL;
        if (ctx->search_filter.x509_issuer)
            X509_NAME_free(ctx->search_filter.x509_issuer);
        ctx->search_filter.x509_issuer = NULL;
        if (ctx->search_filter.alias)
            OPENSSL_free(ctx->search_filter.alias);
        ctx->search_filter.alias = NULL;
        if (ctx->search_filter.serial)
            BN_free(ctx->search_filter.serial);
        ctx->search_filter.serial = NULL;
        if (ctx->search_filter.key_alias)
            OPENSSL_free(ctx->search_filter.key_alias);
        ctx->search_filter.key_alias = NULL;
        if (ctx->search_filter.cert)
            X509_free(ctx->search_filter.cert);
        ctx->search_filter.cert = NULL;
        if (ctx->search_filter.pubkey)
            EVP_PKEY_free(ctx->search_filter.pubkey);
        ctx->search_filter.pubkey = NULL;
        ctx->search_filter.search_flag = 0;
        pkcs11_close_session(ctx->pkcs11_ctx, &ctx->session);
        OPENSSL_free(ctx);
    }

    return 1;
}

OSSL_ALGORITHM *pkcs11_store_get_algo_tbl(const char *id)
{
    OPENSSL_STACK *algo_sk = OPENSSL_sk_new_null();
    OSSL_ALGORITHM *tblalgo = NULL;
    OSSL_ALGORITHM *ptblalgo = NULL;
    OSSL_ALGORITHM* item = NULL;
    int i = 0;
    pkcs11_add_algorithm(algo_sk, "file", id,
                         pkcs11_store_functions,
                         pkcs11_store_description);
    i = OPENSSL_sk_num(algo_sk);
    if (i > 0) {
        tblalgo = OPENSSL_zalloc((i + 1) * sizeof(*tblalgo));
        ptblalgo = (OSSL_ALGORITHM *)tblalgo;
        item = (OSSL_ALGORITHM *)OPENSSL_sk_value(algo_sk, i - 1);
        memcpy(ptblalgo, item, sizeof(*item));
        OPENSSL_free(item);
        OPENSSL_sk_free(algo_sk);
    }
    return tblalgo;
}
