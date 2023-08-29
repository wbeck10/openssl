#include "pkcs11_utils.h"
#include <string.h>

void pkcs11_set_error(PKCS11_CTX *ctx, int reason, const char *file, int line,
                             const char *func, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    if (ctx != NULL) {
        if (ctx->core_new_error != NULL)
            ctx->core_new_error(ctx->ctx.handle);
        if (ctx->core_set_error_debug != NULL)
            ctx->core_set_error_debug(ctx->ctx.handle, file, line, func);
        if (ctx->core_vset_error != NULL)
            ctx->core_vset_error(ctx->ctx.handle, reason, fmt, ap);
    }
    va_end(ap);
}

int pkcs11_add_algorithm(OPENSSL_STACK *stack, const char *algoname,
                         const char *searchstr, const OSSL_DISPATCH *dispatch, const char* description)
{
    OSSL_ALGORITHM *algo = (OSSL_ALGORITHM *)OPENSSL_zalloc(sizeof(OSSL_ALGORITHM));
    if (algo == NULL)
        return 0;
    algo->algorithm_names = algoname;
    algo->property_definition = searchstr;
    algo->implementation = dispatch;
    algo->algorithm_description = description;
    if (!OPENSSL_sk_push(stack, algo)){
        OPENSSL_free(algo);
        return 0;
    }
    return 1;
}

int pkcs11_add_attribute(OPENSSL_STACK *stack, CK_ATTRIBUTE_TYPE type,
                         CK_VOID_PTR pValue, CK_ULONG ulValueLen)
{
    CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *)OPENSSL_zalloc(sizeof(CK_ATTRIBUTE));
    if (attr == NULL)
        return 0;
    attr->type = type;
    attr->pValue = pValue;
    attr->ulValueLen = ulValueLen;
    if (!OPENSSL_sk_push(stack, attr)){
        OPENSSL_free(attr);
        return 0;
    }
    return 1;
}

int pkcs11_get_byte_array(BIGNUM *num, CK_BYTE_PTR *out)
{
    CK_BYTE_PTR val = NULL;
    int len = BN_num_bytes(num);
    if (len == 0) 
        goto end;
    val = (CK_BYTE*)OPENSSL_zalloc(len);
    if (val == NULL)
        goto end;
    len = BN_bn2bin(num, val);
    *out = val;
    return len;
end:
    return -1;
}

PKCS11_SLOT *pkcs11_get_slot(PKCS11_CTX *provctx)
{
    int i = 0;
    PKCS11_SLOT *slot = NULL;

    for (i = 0; i < OPENSSL_sk_num(provctx->slots); i++) {
        slot = (PKCS11_SLOT *)OPENSSL_sk_value(provctx->slots, i);
        if (provctx->sel_token != NULL && strlen((char*)provctx->sel_token) > 0) {
            if (strlen((char*)slot->info.label) > 0) {
                if (strncmp((char*)slot->info.label, (char*)provctx->sel_token,
                            strlen((char*)provctx->sel_token)) == 0) {
                    return slot;
                }
            }
        } else {
            if (slot->slotid == provctx->sel_slot)
            return slot;
        }
    }
    return NULL;
}

CK_ULONG pkcs11_md_nid2ckm(int nid)
{
    switch(nid){
        case NID_sha1:
            return CKM_SHA_1;
        case NID_sha224:
            return CKM_SHA224;
        case NID_sha256:
            return CKM_SHA256;
        case NID_sha384:
            return CKM_SHA384;
        case NID_sha512:
            return CKM_SHA512;
    }
    return CKM_NULL;
}

int pkcs11_open_session(PKCS11_CTX *ctx, CK_SESSION_HANDLE_PTR session)
{
    int ret = 0;
    CK_RV rv = CKR_CANCEL;
    CK_FLAGS flags;
    PKCS11_SLOT *slot = NULL;

    /* Open a user R/W session: all future sessions will be user sessions. */
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    slot = pkcs11_get_slot(ctx);
    if (slot == NULL)
        goto  end;

    rv = pkcs11_get_lib_functions()->C_OpenSession(slot->slotid, flags, NULL, NULL, session);
    if (rv != CKR_OK) {
        SET_PKCS11_PROV_ERR(ctx, rv);
        goto end;
    }

    if (ctx->userpin == NULL) {
        SET_PKCS11_PROV_ERR(ctx, ERR_PKCS11_NO_USERPIN_SET);
        goto end;
    }

    if (slot->info.flags & CKF_LOGIN_REQUIRED) {
        rv = pkcs11_get_lib_functions()->C_Login((*session), CKU_USER,
                                                 ctx->userpin,
                                                 strlen((char *)ctx->userpin));
        if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN) {
            SET_PKCS11_PROV_ERR(ctx, rv);
            goto end;
        }
    }
    ret = 1;
end:
    return ret;
}

void pkcs11_close_session(PKCS11_CTX *ctx, CK_SESSION_HANDLE_PTR session)
{
    if ((*session) != 0) {
        /* TODO Opencryptoki and Ultimaco have trouble with logout
         * If logout is called, test_Store_Search will raise errors in
         * pkcs11_keymgmt_load when calling pkcs11_keymgmt_get_keyhandle_from_keyparam
         * CKR_OBJECT_HANDLE_INVALID
         */
        /* pkcs11_get_lib_functions()->C_Logout((*session)); */
        pkcs11_get_lib_functions()->C_CloseSession((*session));
        *session = 0;
    }
}

CK_ULONG pkcs11_md_nid2ckm_mgf1(int nid)
{
    switch(nid){
        case NID_sha1:
            return CKG_MGF1_SHA1;
        case NID_sha224:
            return CKG_MGF1_SHA224;
        case NID_sha256:
            return CKG_MGF1_SHA256;
        case NID_sha384:
            return CKG_MGF1_SHA384;
        case NID_sha512:
            return CKG_MGF1_SHA512;
    }
    return CKM_NULL;
}
