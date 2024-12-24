/*
 * $Id$
 * 'OpenSSL for Ruby' project
 * Copyright (C) 2001-2002  Michal Rokos <m.rokos@sh.cvut.cz>
 * All rights reserved.
 */
/*
 * This program is licenced under the same licence as Ruby.
 * (See the file 'LICENCE'.)
 */
#include RUBY_EXTCONF_H

#if defined(HAVE_OPENSSL_ENGINE_H) && defined(HAVE_ST_ENGINE)
# include <openssl/engine.h>
#endif
#include <openssl/x509_vfy.h>

#if !defined(OPENSSL_NO_HMAC)
#include <string.h> /* memcpy() */
#include <openssl/hmac.h>

#include "openssl_missing.h"

#if !defined(HAVE_HMAC_CTX_COPY)
void
HMAC_CTX_copy(HMAC_CTX *out, HMAC_CTX *in)
{
    if (!out || !in) return;
    memcpy(out, in, sizeof(HMAC_CTX));

    EVP_MD_CTX_copy(&out->md_ctx, &in->md_ctx);
    EVP_MD_CTX_copy(&out->i_ctx, &in->i_ctx);
    EVP_MD_CTX_copy(&out->o_ctx, &in->o_ctx);
}
#endif /* HAVE_HMAC_CTX_COPY */
#endif /* NO_HMAC */

#if !defined(HAVE_X509_STORE_SET_EX_DATA)
int X509_STORE_set_ex_data(X509_STORE *str, int idx, void *data)
{
    return CRYPTO_set_ex_data(&str->ex_data, idx, data);
}
#endif

#if !defined(HAVE_X509_STORE_GET_EX_DATA)
void *X509_STORE_get_ex_data(X509_STORE *str, int idx)
{
    return CRYPTO_get_ex_data(&str->ex_data, idx);
}
#endif

#if !defined(HAVE_X509_CRL_SET_VERSION)
int
X509_CRL_set_version(X509_CRL *x, long version)
{
    if (x == NULL || x->crl == NULL) return 0;
    if (x->crl->version == NULL) {
	x->crl->version = M_ASN1_INTEGER_new();
	if (x->crl->version == NULL) return 0;
    }
    return ASN1_INTEGER_set(x->crl->version, version);
}
#endif

#if !defined(HAVE_X509_CRL_SET_ISSUER_NAME)
int
X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name)
{
    if (x == NULL || x->crl == NULL) return 0;
    return X509_NAME_set(&x->crl->issuer, name);
}
#endif

#if !defined(HAVE_X509_CRL_SORT)
int
X509_CRL_sort(X509_CRL *c)
{
    int i;
    X509_REVOKED *r;
    /* sort the data so it will be written in serial
     * number order */
    sk_X509_REVOKED_sort(c->crl->revoked);
    for (i=0; i<sk_X509_REVOKED_num(c->crl->revoked); i++) {
	r=sk_X509_REVOKED_value(c->crl->revoked, i);
	r->sequence=i;
    }
    return 1;
}
#endif

#if !defined(HAVE_BN_RAND_RANGE) || !defined(HAVE_BN_PSEUDO_RAND_RANGE)
static int
bn_rand_range(int pseudo, BIGNUM *r, BIGNUM *range)
{
    int (*bn_rand)(BIGNUM *, int, int, int) = pseudo ? BN_pseudo_rand : BN_rand;
    int n;

    if (range->neg || BN_is_zero(range)) return 0;

    n = BN_num_bits(range);

    if (n == 1) {
	if (!BN_zero(r)) return 0;
    } else if (!BN_is_bit_set(range, n - 2) && !BN_is_bit_set(range, n - 3)) {
	do {
	    if (!bn_rand(r, n + 1, -1, 0)) return 0;
	    if (BN_cmp(r ,range) >= 0) {
		if (!BN_sub(r, r, range)) return 0;
		if (BN_cmp(r, range) >= 0)
		    if (!BN_sub(r, r, range)) return 0;
	    }
	} while (BN_cmp(r, range) >= 0);
    } else {
	do {
	    if (!bn_rand(r, n, -1, 0)) return 0;
	} while (BN_cmp(r, range) >= 0);
    }

    return 1;
}
#endif
