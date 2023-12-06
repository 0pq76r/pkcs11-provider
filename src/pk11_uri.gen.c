/* DO NOT EDIT, autogenerated from src/pk11_uri.pre */
/* Modify src/pk11_uri.pre then run make generate-code */

extern P11PROV_PK11_URI *P11PROV_PK11_URI_new(void);
extern void P11PROV_PK11_URI_free(P11PROV_PK11_URI *a);
extern P11PROV_PK11_URI *
d2i_P11PROV_PK11_URI(P11PROV_PK11_URI **a, const unsigned char **in, long len);
extern int i2d_P11PROV_PK11_URI(const P11PROV_PK11_URI *a, unsigned char **out);
extern const ASN1_ITEM *P11PROV_PK11_URI_it(void);

P11PROV_PK11_URI
*d2i_P11PROV_PK11_URI(P11PROV_PK11_URI **a, const unsigned char **in, long len)
{
    return (P11PROV_PK11_URI *)ASN1_item_d2i((ASN1_VALUE **)a, in, len,
                                             (P11PROV_PK11_URI_it()));
}
int i2d_P11PROV_PK11_URI(const P11PROV_PK11_URI *a, unsigned char **out)
{
    return ASN1_item_i2d((const ASN1_VALUE *)a, out, (P11PROV_PK11_URI_it()));
}
P11PROV_PK11_URI
*P11PROV_PK11_URI_new(void)
{
    return (P11PROV_PK11_URI *)ASN1_item_new((P11PROV_PK11_URI_it()));
}
void P11PROV_PK11_URI_free(P11PROV_PK11_URI *a)
{
    ASN1_item_free((ASN1_VALUE *)a, (P11PROV_PK11_URI_it()));
}

static const ASN1_TEMPLATE P11PROV_PK11_URI_seq_tt[] = {

    { (0), (0), __builtin_offsetof(P11PROV_PK11_URI, type), "type",
      (ASN1_OBJECT_it) },

    { (0), (0), __builtin_offsetof(P11PROV_PK11_URI, uri), "uri",
      (ASN1_UTF8STRING_it) },
};
const ASN1_ITEM *P11PROV_PK11_URI_it(void)
{
    static const ASN1_ITEM local_it = { 0x1,
                                        16,
                                        P11PROV_PK11_URI_seq_tt,
                                        sizeof(P11PROV_PK11_URI_seq_tt)
                                            / sizeof(ASN1_TEMPLATE),
                                        ((void *)0),
                                        sizeof(P11PROV_PK11_URI),
                                        "P11PROV_PK11_URI" };
    return &local_it;
}

extern int PEM_write_bio_P11PROV_PK11_URI(BIO *out, const P11PROV_PK11_URI *x);
int PEM_write_bio_P11PROV_PK11_URI(BIO *out, const P11PROV_PK11_URI *x)
{
    return PEM_ASN1_write_bio((i2d_of_void *)i2d_P11PROV_PK11_URI,
                              P11PROV_PRIVKEY_PEM_NAME, out, x, ((void *)0),
                              ((void *)0), 0, ((void *)0), ((void *)0));
}

extern P11PROV_PK11_URI *PEM_read_bio_P11PROV_PK11_URI(BIO *out,
                                                       P11PROV_PK11_URI **x,
                                                       pem_password_cb *cb,
                                                       void *u);

P11PROV_PK11_URI
*PEM_read_bio_P11PROV_PK11_URI(BIO *bp, P11PROV_PK11_URI **x,
                               pem_password_cb *cb, void *u)
{
    return PEM_ASN1_read_bio((d2i_of_void *)d2i_P11PROV_PK11_URI,
                             P11PROV_PRIVKEY_PEM_NAME, bp, (void **)x, cb, u);
}
