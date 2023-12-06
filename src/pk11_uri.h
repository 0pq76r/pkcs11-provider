/* Copyright (C) 2022 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0 */

#ifndef _PK11_URI_H
#define _PK11_URI_H

#include <openssl/asn1t.h>

#define P11PROV_OID_URI "2.5.4.83" /* TODO: find a more appropriate oId */
#define P11PROV_PK11_URI_STRUCTURE "pk11-uri"
#define P11PROV_PRIVKEY_PEM_NAME "PRIVATE KEY PK11-URI"

typedef struct {
    ASN1_OBJECT *type;
    ASN1_UTF8STRING *uri;
} P11PROV_PK11_URI;

extern P11PROV_PK11_URI *P11PROV_PK11_URI_new(void);
extern void P11PROV_PK11_URI_free(P11PROV_PK11_URI *a);
extern P11PROV_PK11_URI *
d2i_P11PROV_PK11_URI(P11PROV_PK11_URI **a, const unsigned char **in, long len);
extern P11PROV_PK11_URI *PEM_read_bio_P11PROV_PK11_URI(BIO *out,
                                                       P11PROV_PK11_URI **x,
                                                       pem_password_cb *cb,
                                                       void *u);
extern int PEM_write_bio_P11PROV_PK11_URI(BIO *out, const P11PROV_PK11_URI *x);

#endif
