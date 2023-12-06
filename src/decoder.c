/* Copyright (C) 2023 Simo Sorce <simo@redhat.com>
   SPDX-License-Identifier: Apache-2.0
*/

#include "provider.h"
#include "decoder.h"
#include "pk11_uri.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/core_dispatch.h>
#include <openssl/store.h>
#include <openssl/ui.h>

#define MAX_OID_LEN 64

typedef struct p11prov_decoder_ctx {
    P11PROV_CTX *provctx;
    P11PROV_OBJ *object;
    bool invalid;
} P11PROV_DECODER_CTX;

static bool decoder_ctx_accepts_decoded_object(P11PROV_DECODER_CTX *ctx)
{
    return (!ctx->invalid) && (ctx->object == NULL);
}

static void decoder_ctx_object_free(struct p11prov_decoder_ctx *ctx)
{
    if (ctx && ctx->object) {
        p11prov_obj_free(ctx->object);
        ctx->object = NULL;
    }
}

static void *p11prov_decoder_newctx(void *provctx)
{
    P11PROV_CTX *cprov;
    P11PROV_DECODER_CTX *dctx;
    cprov = provctx;
    dctx = OPENSSL_zalloc(sizeof(P11PROV_DECODER_CTX));
    if (dctx == NULL) {
        return NULL;
    }

    dctx->provctx = cprov;
    return dctx;
}

static void p11prov_decoder_freectx(void *inctx)
{
    P11PROV_DECODER_CTX *ctx = inctx;

    decoder_ctx_object_free(ctx);
    OPENSSL_clear_free(ctx, sizeof(P11PROV_DECODER_CTX));
}

static CK_RV p11prov_decoder_ctx_store_obj(void *pctx, P11PROV_OBJ *obj)
{
    P11PROV_DECODER_CTX *ctx = pctx;

    if (!decoder_ctx_accepts_decoded_object(ctx)) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR,
                      "Invalid decoder context");
        ctx->invalid = 1;
        decoder_ctx_object_free(ctx);
        p11prov_obj_free(obj);
        return CKR_GENERAL_ERROR;
    }

    P11PROV_debug("Adding object (handle:%lu)", p11prov_obj_get_handle(obj));
    if (p11prov_obj_get_class(obj) != CKO_PRIVATE_KEY) {
        P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD,
                      "Object must be private key");
        p11prov_obj_free(obj);
        return CKR_ARGUMENTS_BAD;
    }

    ctx->object = obj;

    return CKR_OK;
}

static CK_RV p11prov_decoder_load_pkey(P11PROV_DECODER_CTX *ctx,
                                       const char *inuri,
                                       OSSL_PASSPHRASE_CALLBACK *pw_cb,
                                       void *pw_cbarg)
{
    P11PROV_URI *parsed_uri = NULL;
    CK_RV ret = CKR_GENERAL_ERROR;
    P11PROV_SESSION *session = NULL;
    CK_SLOT_ID slotid = CK_UNAVAILABLE_INFORMATION;
    CK_SLOT_ID nextid = CK_UNAVAILABLE_INFORMATION;

    if (!decoder_ctx_accepts_decoded_object(ctx)) {
        P11PROV_debug("Invalid context state");
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Invalid initial state");
        goto done;
    }

    parsed_uri = p11prov_parse_uri(ctx->provctx, inuri);
    if (parsed_uri == NULL) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to parse URI");
        goto done;
    }

    ret = p11prov_ctx_status(ctx->provctx);
    if (ret != CKR_OK) {
        P11PROV_raise(ctx->provctx, ret, "Invalid context status");
        goto done;
    }

    p11prov_set_error_mark(ctx->provctx);
    do {
        nextid = CK_UNAVAILABLE_INFORMATION;
        p11prov_return_session(session);
        if (!decoder_ctx_accepts_decoded_object(ctx)) {
            break;
        }

        ret = p11prov_get_session(ctx->provctx, &slotid, &nextid, parsed_uri,
                                  CK_UNAVAILABLE_INFORMATION, pw_cb, pw_cbarg,
                                  true, false, &session);
        if (ret != CKR_OK) {
            P11PROV_debug(
                "Failed to get session to load keys (slotid=%lx, ret=%lx)",
                slotid, ret);
            slotid = nextid;
            continue;
        }

        ret = p11prov_obj_find(ctx->provctx, session, slotid, parsed_uri,
                               p11prov_decoder_ctx_store_obj, ctx);
        if (ret != CKR_OK) {
            P11PROV_debug(
                "Failed to find object on (slotid=%lx, session=%lx, ret=%lx)",
                slotid, session, ret);
            slotid = nextid;
            continue;
        }
        slotid = nextid;
    } while (nextid != CK_UNAVAILABLE_INFORMATION);
    ret = CKR_OK;
    p11prov_pop_error_to_mark(ctx->provctx);
    p11prov_clear_last_error_mark(ctx->provctx);

    if (ctx->invalid) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(ctx->provctx, ret, "Invalid context status");
        goto done;
    }

    if (!ctx->object) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_raise(ctx->provctx, ret, "No matching object stored");
        goto done;
    }

    if (p11prov_obj_get_class(ctx->object) != CKO_PRIVATE_KEY) {
        ret = CKR_ARGUMENTS_BAD;
        P11PROV_raise(ctx->provctx, ret,
                      "Referenced object is not a private key");
        goto done;
    }

done:
    p11prov_uri_free(parsed_uri);
    p11prov_return_session(session);
    if (ret != CKR_OK) {
        decoder_ctx_object_free(ctx);
    }

    P11PROV_debug("Done (result:%d)", ret);
    return ret;
}

static int
p11prov_decoder_decode_p11pkey(CK_KEY_TYPE desired_key_type, void *inctx,
                               OSSL_CORE_BIO *cin, int selection,
                               OSSL_CALLBACK *object_cb, void *object_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    P11PROV_DECODER_CTX *ctx = inctx;
    P11PROV_PK11_URI *key = NULL;
    BIO *bin;
    int ret = 0;
    const char *uri = NULL;

    P11PROV_debug("P11 KEY DECODER DECODE (selection:0x%x)", selection);
    if ((bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin))
        == NULL) {
        P11PROV_debug("P11 KEY DECODER BIO_new_from_core_bio failed");
        goto done;
    }

    const char *data_type = NULL;
    switch (desired_key_type) {
    case CKK_RSA:
        data_type = P11PROV_NAME_RSA;
        break;
    case CKK_EC:
        data_type = P11PROV_NAME_EC;
        break;
    default:
        ret = 0;
        P11PROV_raise(ctx->provctx, CKR_ARGUMENTS_BAD, "Unsupported key type");
        goto done;
    }

    const unsigned char *der;
    long der_len = BIO_get_mem_data(bin, &der);
    if (der_len <= 0) {
        P11PROV_debug("P11 KEY DECODER BIO_get_mem_data failed");
        ret = 1;
        goto done;
    }
    if ((key = d2i_P11PROV_PK11_URI(NULL, &der, der_len)) == NULL) {
        P11PROV_debug("P11 KEY DECODER d2i_P11PROV_PK11_URI failed");
        ret = 1;
        goto done;
    }

    char oid_txt[MAX_OID_LEN];
    if (OBJ_obj2txt(oid_txt, sizeof(oid_txt), key->type, 1) > 0) {
        P11PROV_debug("P11 KEY DECODER got OID %s", oid_txt);
    } else {
        P11PROV_debug("P11 KEY DECODER OBJ_obj2txt failed");
        goto done;
    }

    uri = (const char *)ASN1_STRING_get0_data(key->uri);
    if (uri == NULL) {
        P11PROV_raise(ctx->provctx, CKR_GENERAL_ERROR, "Failed to get URI");
        goto done;
    }

    if (p11prov_decoder_load_pkey(ctx, uri, pw_cb, pw_cbarg) != CKR_OK) {
        P11PROV_debug("P11 KEY DECODER p11prov_decoder_load_key failed");
        goto done;
    }

    if (p11prov_obj_get_key_type(ctx->object) != desired_key_type) {
        P11PROV_debug(
            "P11 KEY DECODER p11prov_decoder_load_key wrong key type");
        ret = 1;
        goto done;
    }

    P11PROV_debug("P11 KEY DECODER p11prov_decoder_load_key OK");

    void *key_reference = NULL;
    size_t key_reference_sz = 0;
    p11prov_obj_to_store_reference(ctx->object, &key_reference,
                                   &key_reference_sz);

    int object_type = OSSL_OBJECT_PKEY;
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)data_type, 0);
    /* The address of the key becomes the octet string */
    params[2] = OSSL_PARAM_construct_octet_string(
        OSSL_OBJECT_PARAM_REFERENCE, key_reference, key_reference_sz);
    params[3] = OSSL_PARAM_construct_end();
    object_cb(params, object_cbarg);

done:
    decoder_ctx_object_free(ctx);
    P11PROV_PK11_URI_free(key);
    BIO_free(bin);
    P11PROV_debug("P11 KEY DECODER RESULT=%d", ret);
    return ret;
}

static int p11prov_der_decoder_p11_rsa_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return p11prov_decoder_decode_p11pkey(CKK_RSA, inctx, cin, selection,
                                          object_cb, object_cbarg, pw_cb,
                                          pw_cbarg);
}

const OSSL_DISPATCH p11prov_der_decoder_p11_rsa_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, der, p11, rsa, decode),
    { 0, NULL }
};

static int p11prov_der_decoder_p11_ec_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return p11prov_decoder_decode_p11pkey(CKK_EC, inctx, cin, selection,
                                          object_cb, object_cbarg, pw_cb,
                                          pw_cbarg);
}

const OSSL_DISPATCH p11prov_der_decoder_p11_ec_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, der, p11, ec, decode),
    { 0, NULL }
};

static int p11prov_pem_decoder_p11_der_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{

    BIO *bin;
    char *pem_name;
    char *pem_header;
    unsigned char *der_data;
    long der_len;
    OSSL_PARAM params[3];
    int ret;
    P11PROV_DECODER_CTX *ctx = inctx;

    P11PROV_debug("DER DECODER DECODE (selection:0x%x)", selection);

    if ((bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin))
        == NULL) {
        P11PROV_debug("BIO_new_from_core_bio failed");
        return 0;
    }
    P11PROV_debug("DER DECODER PEM_read_pio (fpos:%u)", BIO_tell(bin));

    if (PEM_read_bio(bin, &pem_name, &pem_header, &der_data, &der_len) > 0
        && strcmp(pem_name, P11PROV_PRIVKEY_PEM_NAME) == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      der_data, der_len);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE,
            (char *)P11PROV_PK11_URI_STRUCTURE, 0);
        params[2] = OSSL_PARAM_construct_end();
        ret = object_cb(params, object_cbarg);
    } else {
        /* We return "empty handed". This is not an error. */
        ret = 1;
    }

    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    BIO_free(bin);

    P11PROV_debug("DER DECODER RESULT=%d", ret);
    return ret;
}

const OSSL_DISPATCH p11prov_pem_decoder_p11_der_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, pem, p11, der, decode),
    { 0, NULL }
};
