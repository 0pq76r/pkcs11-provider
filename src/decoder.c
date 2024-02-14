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

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

typedef struct p11prov_decoder_ctx {
    P11PROV_CTX *provctx;
    P11PROV_OBJ *object;
    bool invalid;
} P11PROV_DECODER_CTX;

static int p11prov_obj_to_ossl_obj(P11PROV_OBJ *obj, OSSL_PARAM params[4])
{
    int object_type;
    const char *data_type;
    void *reference = NULL;
    size_t reference_len;
    CK_KEY_TYPE type;
    CK_ATTRIBUTE *cert = NULL;
    switch (p11prov_obj_get_class(obj)) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        object_type = OSSL_OBJECT_PKEY;
        type = p11prov_obj_get_key_type(obj);
        switch (type) {
        case CKK_RSA:
            data_type = P11PROV_NAME_RSA;
            break;
        case CKK_EC:
            data_type = P11PROV_NAME_EC;
            break;
        case CKK_EC_EDWARDS:
            switch (p11prov_obj_get_key_bit_size(obj)) {
            case ED448_BIT_SIZE:
                data_type = ED448;
                break;
            case ED25519_BIT_SIZE:
                data_type = ED25519;
                break;
            default:
                return RET_OSSL_ERR;
            }
            break;
        default:
            return RET_OSSL_ERR;
        }
        p11prov_obj_to_store_reference(obj, &reference, &reference_len);
        if (!reference) {
            return RET_OSSL_ERR;
        }
        break;
    case CKO_CERTIFICATE:
        object_type = OSSL_OBJECT_CERT;
        data_type = "CERTIFICATE";
        cert = p11prov_obj_get_attr(obj, CKA_VALUE);
        if (!cert) {
            return RET_OSSL_ERR;
        }
        break;
    default:
        return RET_OSSL_ERR;
    }

    params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                 (char *)data_type, 0);
    if (reference) {
        /* giving away the object by reference */
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_REFERENCE, reference, reference_len);
    } else if (cert) {
        params[2] = OSSL_PARAM_construct_octet_string(
            OSSL_OBJECT_PARAM_DATA, cert->pValue, cert->ulValueLen);
    } else {
        return RET_OSSL_ERR;
    }
    params[3] = OSSL_PARAM_construct_end();
    return RET_OSSL_OK;
}

static bool decoder_ctx_accepts_decoded_object(P11PROV_DECODER_CTX *ctx)
{
    return (!ctx->invalid) && (!ctx->object);
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
    if (!dctx) {
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
                      "decoder context does not accept any objects");
        ctx->invalid = 1;
        decoder_ctx_object_free(ctx);
        p11prov_obj_free(obj);
        return CKR_GENERAL_ERROR;
    }

    P11PROV_debug("Adding object (handle:%lu)", p11prov_obj_get_handle(obj));
    ctx->object = obj;

    return CKR_OK;
}

static CK_RV p11prov_decoder_load_obj(P11PROV_DECODER_CTX *ctx,
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
        P11PROV_debug("Invalid initial state");
        goto done;
    }

    parsed_uri = p11prov_parse_uri(ctx->provctx, inuri);
    if (!parsed_uri) {
        P11PROV_debug("Failed to parse URI");
        goto done;
    }

    ret = p11prov_ctx_status(ctx->provctx);
    if (ret != CKR_OK) {
        P11PROV_debug("Invalid context status");
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
        P11PROV_debug("Invalid context status");
        goto done;
    }

    if (!ctx->object) {
        ret = CKR_GENERAL_ERROR;
        P11PROV_debug("No matching object stored");
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

static int obj_desc_verify(P11PROV_PK11_URI *obj)
{
    const char *desc = NULL;
    int desc_len;
    desc = (const char *)ASN1_STRING_get0_data(obj->desc);
    desc_len = ASN1_STRING_length(obj->desc);
    if (!desc || desc_len <= 0) {
        P11PROV_debug("Failed to get description");
        return RET_OSSL_ERR;
    }

    if (desc_len != (sizeof(P11PROV_DESCS_URI_FILE) - 1)
        || 0 != strncmp(desc, P11PROV_DESCS_URI_FILE, desc_len)) {
        P11PROV_debug("Description string does not match");
        return RET_OSSL_ERR;
    }
    return RET_OSSL_OK;
}

static int p11prov_der_decoder_p11prov_obj_decode(
    const char *desired_data_type, void *inctx, OSSL_CORE_BIO *cin,
    int selection, OSSL_CALLBACK *object_cb, void *object_cbarg,
    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    P11PROV_DECODER_CTX *const ctx = inctx;
    P11PROV_PK11_URI *obj = NULL;
    BIO *bin;
    int ret = RET_OSSL_CARRY_ON_DECODING;
    const char *uri = NULL;
    int uri_len;

    bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin);
    if (!bin) {
        P11PROV_debug("P11 DECODER BIO_new_from_core_bio failed");
        goto done;
    }

    const unsigned char *der;
    long der_len = BIO_get_mem_data(bin, &der);
    if (der_len <= 0) {
        P11PROV_debug("P11 DECODER BIO_get_mem_data failed");
        goto done;
    }
    obj = d2i_P11PROV_PK11_URI(NULL, &der, der_len);
    if (!obj) {
        P11PROV_debug("P11 KEY DECODER d2i_P11PROV_PK11_URI failed");
        goto done;
    }

    if (!obj_desc_verify(obj)) {
        goto done;
    }

    uri = (const char *)ASN1_STRING_get0_data(obj->uri);
    uri_len = ASN1_STRING_length(obj->uri);
    /* todo check string ends in \0 */
    if (!uri || uri_len <= 0) {
        P11PROV_debug("Failed to get URI");
        goto done;
    }

    if (p11prov_decoder_load_obj(ctx, uri, pw_cb, pw_cbarg) != CKR_OK) {
        goto done;
    }

    OSSL_PARAM params[4];
    if (!p11prov_obj_to_ossl_obj(ctx->object, params)) {
        P11PROV_debug("Failed to turn p11prov obj into an OSSL_OBJECT");
        goto done;
    };

    if (0 == strcmp(params[1].key, "data-type")
        && 0 == strcmp(params[1].data, desired_data_type)) {
        ret = object_cb(params, object_cbarg);
    }

done:
    decoder_ctx_object_free(ctx);
    P11PROV_PK11_URI_free(obj);
    BIO_free(bin);
    P11PROV_debug("der decoder (cary on:%d)", ret);
    return ret;
}

static int p11prov_der_decoder_p11prov_rsa_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return p11prov_der_decoder_p11prov_obj_decode(
        P11PROV_NAME_RSA, inctx, cin, selection, object_cb, object_cbarg, pw_cb,
        pw_cbarg);
}

const OSSL_DISPATCH p11prov_der_decoder_p11prov_rsa_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, der, p11prov, rsa, decode),
    { 0, NULL }
};

static int p11prov_der_decoder_p11prov_ec_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    return p11prov_der_decoder_p11prov_obj_decode(
        P11PROV_NAME_EC, inctx, cin, selection, object_cb, object_cbarg, pw_cb,
        pw_cbarg);
}

const OSSL_DISPATCH p11prov_der_decoder_p11prov_ec_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, der, p11prov, ec, decode),
    { 0, NULL }
};

static int p11prov_pem_decoder_p11prov_der_decode(
    void *inctx, OSSL_CORE_BIO *cin, int selection, OSSL_CALLBACK *object_cb,
    void *object_cbarg, OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{

    BIO *bin;
    char *pem_label;
    char *pem_header;
    unsigned char *der_data;
    long der_len;
    OSSL_PARAM params[3];
    int ret = RET_OSSL_CARRY_ON_DECODING;
    P11PROV_DECODER_CTX *ctx = inctx;

    bin = BIO_new_from_core_bio(p11prov_ctx_get_libctx(ctx->provctx), cin);
    if (!bin) {
        P11PROV_debug("BIO_new_from_core_bio failed");
        return RET_OSSL_CARRY_ON_DECODING;
    }

    P11PROV_debug("PEM_read_pio (fpos:%u)", BIO_tell(bin));

    if (PEM_read_bio(bin, &pem_label, &pem_header, &der_data, &der_len) > 0
        && strcmp(pem_label, P11PROV_PEM_LABEL) == 0) {
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                      der_data, der_len);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_OBJECT_PARAM_DATA_STRUCTURE, (char *)P11PROV_DER_STRUCTURE, 0);
        params[2] = OSSL_PARAM_construct_end();
        ret = object_cb(params, object_cbarg);
    }

    OPENSSL_free(pem_label);
    OPENSSL_free(pem_header);
    OPENSSL_free(der_data);
    BIO_free(bin);

    P11PROV_debug("pem decoder (carry on:%d)", ret);
    return ret;
}

const OSSL_DISPATCH p11prov_pem_decoder_p11prov_der_functions[] = {
    DISPATCH_BASE_DECODER_ELEM(NEWCTX, newctx),
    DISPATCH_BASE_DECODER_ELEM(FREECTX, freectx),
    DISPATCH_DECODER_ELEM(DECODE, pem, p11prov, der, decode),
    { 0, NULL }
};
