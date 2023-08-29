#ifndef PKCS11_KEYMGMT_H
# define PKCS11_KEYMGMT_H

#include <prov/providercommon.h>
#include "pkcs11_ctx.h"

OSSL_ALGORITHM *pkcs11_keymgmt_get_algo_tbl(OPENSSL_STACK *sk, const char *id);
CK_OBJECT_HANDLE pkcs11_keymgmt_get_keyhandle_from_keyparam(PKCS11_CTX* ctx,
                                                            PKCS11_KEY *key,
                                                            CK_SESSION_HANDLE_PTR session);
int pkcs11_keymgmt_get_keyparam_from_key(PKCS11_CTX* ctx,
                                         PKCS11_KEY *key, CK_OBJECT_HANDLE keyhandle,
                                         CK_SESSION_HANDLE session,
                                         int is_private);
int pkcs11_keymgmt_update_key(PKCS11_CTX* ctx, PKCS11_KEY *key,
                              CK_OBJECT_HANDLE keyhandle,
                              CK_SESSION_HANDLE session,
                              char *label, int label_len,
                              unsigned char *id, int id_len);
int pkcs11_keymgmt_rm_tmp_gen_key(unsigned char* id, int id_len);
void pkcs11_keygmgmt_create_lock(void);
void pkcs11_keygmgmt_free_lock(void);
#endif /* PKCS11_KEYMGMT_H */

