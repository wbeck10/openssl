 
#ifndef PKCS11_CIPHER_H
# define PKCS11_CIPHER_H

#include <prov/providercommon.h>
#include "pkcs11_ctx.h"

OSSL_ALGORITHM *pkcs11_asym_cipher_get_algo_tbl(OPENSSL_STACK *sk, const char *id);

#endif /* PKCS11_CIPHER_H */
