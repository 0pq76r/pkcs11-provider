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

typedef struct p11prov_decoder_ctx {
    P11PROV_CTX *provctx;
} P11PROV_DECODER_CTX;

static void *p11prov_decoder_newctx(void *provctx)
{
    P11PROV_DECODER_CTX *dctx;
    dctx = OPENSSL_zalloc(sizeof(P11PROV_DECODER_CTX));
    if (!dctx) {
        return NULL;
    }

    dctx->provctx = provctx;
    return dctx;
}

static void p11prov_decoder_freectx(void *ctx)
{
    OPENSSL_clear_free(ctx, sizeof(P11PROV_DECODER_CTX));
}

struct desired_type_match_data {
    const char *desired_type;
    bool matches;
};

static void desired_type_accumulate_matches(const char *name, void *data)
{
    struct desired_type_match_data *type_match = data;
    P11PROV_debug("'%s' ?= '%s'", name ,type_match->desired_type);
    type_match->matches |= 0 == OPENSSL_strcasecmp(name, type_match->desired_type);
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

static char *obj_uri_get1(P11PROV_PK11_URI *obj)
{
    const unsigned char *uri = ASN1_STRING_get0_data(obj->uri);
    int uri_len = ASN1_STRING_length(obj->uri);
    if (!uri || uri_len <= 0) {
        P11PROV_debug("Failed to get URI");
        return NULL;
    }
    char *null_terminated_uri = OPENSSL_zalloc(uri_len + 1);
    if (!null_terminated_uri) {
        return NULL;
    }
    memcpy(null_terminated_uri, uri, uri_len);
    return null_terminated_uri;
}

static int ui_open(UI *ui)
{
    return 1;
}

static int ui_write(UI *ui, UI_STRING *uis)
{
    return 1;
}

static int ui_close(UI *ui)
{
    return 1;
}

struct pw_cb_data {
    OSSL_PASSPHRASE_CALLBACK *cb;
    void *cbarg;
};

static int ui_read(UI *ui, UI_STRING *uis)
{
    switch (UI_get_string_type(uis)) {
    case UIT_PROMPT: {
        const int bufsize = 1024;
        char result[bufsize + 1];
        struct pw_cb_data *pw = UI_get0_user_data(ui);
        int maxsize = UI_get_result_maxsize(uis);
        size_t len;
        if (pw->cb(result, maxsize > bufsize ? bufsize : maxsize, &len, NULL,
                   pw->cbarg)) {
            if (len >= 0) result[len] = '\0';
            if (UI_set_result_ex(ui, uis, result, len) >= 0) return 1;
            return 0;
        }
    }
    case UIT_VERIFY:
    case UIT_NONE:
    case UIT_BOOLEAN:
    case UIT_INFO:
    case UIT_ERROR:
        break;
    }
    return 1;
}

static UI_METHOD *wrap_passphrase_callback(OSSL_PASSPHRASE_CALLBACK *pw_cb)
{
    UI_METHOD *ui_method = UI_create_method("OSSL_PASSPHRASE_CALLBACK wrapper");

    if (!ui_method || UI_method_set_opener(ui_method, ui_open) < 0
        || UI_method_set_reader(ui_method, ui_read) < 0
        || UI_method_set_writer(ui_method, ui_write) < 0
        || UI_method_set_closer(ui_method, ui_close) < 0) {
        UI_destroy_method(ui_method);
        return NULL;
    }
    return ui_method;
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
    char *uri = NULL;
    OSSL_STORE_CTX *store_ctx = NULL;

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

    uri = obj_uri_get1(obj);
    if (!uri) {
        goto done;
    }

    p11prov_set_error_mark(ctx->provctx);

    UI_METHOD *ui_method = wrap_passphrase_callback(pw_cb);
    struct pw_cb_data pw = { pw_cb, pw_cbarg };
    if ((store_ctx = OSSL_STORE_open_ex(uri, NULL, NULL, ui_method, &pw, NULL,
                                        NULL, NULL))
        == NULL) {
        P11PROV_debug("Couldn't open file or uri %s\n", uri);
        goto done;
    }

    for (;;) {
        OSSL_STORE_INFO *info = OSSL_STORE_load(store_ctx);
        int type = info == NULL ? 0 : OSSL_STORE_INFO_get_type(info);

        if (!info) {
            if (OSSL_STORE_eof(store_ctx)) {
                break;
            }
            if (OSSL_STORE_error(store_ctx)) {
                continue;
            }
            break;
        }

        EVP_PKEY *pkey = NULL;
        switch (type) {
        case OSSL_STORE_INFO_PARAMS:
            P11PROV_debug("OSSL_STORE_INFO_PARAMS");
            pkey = OSSL_STORE_INFO_get0_PARAMS(info);
            break;
        case OSSL_STORE_INFO_PUBKEY:
            P11PROV_debug("OSSL_STORE_INFO_PUBKEY");
            pkey = OSSL_STORE_INFO_get0_PUBKEY(info);
            break;
        case OSSL_STORE_INFO_PKEY:
            P11PROV_debug("OSSL_STORE_INFO_PKEY");
            pkey = OSSL_STORE_INFO_get0_PKEY(info);
            break;
        }
        if (pkey) {
            struct desired_type_match_data type_match_data = { 0 };
            type_match_data.desired_type = desired_data_type;
            EVP_PKEY_type_names_do_all(pkey, desired_type_accumulate_matches,
                                       &type_match_data);
            if (type_match_data.matches) {
                OSSL_PARAM *params = NULL;
                if (EVP_PKEY_todata(pkey, 0, &params)) {
                    ret = object_cb(params, object_cbarg);
                }
                OSSL_PARAM_free(params);
            } else {
                P11PROV_debug("NO type match");
            }
        } else {
            P11PROV_debug("NO pkey");
        }
        OSSL_STORE_INFO_free(info);
    }

    p11prov_pop_error_to_mark(ctx->provctx);
    p11prov_clear_last_error_mark(ctx->provctx);

done:
    OSSL_STORE_close(store_ctx);
    OPENSSL_free(uri);
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
