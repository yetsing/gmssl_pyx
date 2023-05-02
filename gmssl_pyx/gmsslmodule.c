/*
 * GmSSL sm2 python c extension
 */
#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "gmssl/sm2.h"
#include "gmssl/sm3.h"
#include "gmssl/sm4.h"

#define GMSSL_INNER_OK 1

static PyObject *GmsslInnerError;

static PyObject *InvalidValueError;

static PyObject *
gmsslext_sm2_key_generate(PyObject *self, PyObject *args) {
    SM2_KEY sm2_key;
    int ret, ok;

    // sm2_key_generate() -> t.Tuple[bytes, bytes]
    // 函数没有参数
    ok = PyArg_ParseTuple(args, "");
    if (!ok) {
        return NULL;
    }
    ret = sm2_key_generate(&sm2_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_key_generate");
        return NULL;
    }
    // 整数字面量不是 Py_ssize_t 类型，需要强制转换，不然 Windows 会报错 MemoryError
    return Py_BuildValue("y#y#", &sm2_key.public_key, (Py_ssize_t) 64, &sm2_key.private_key, (Py_ssize_t) 32);
}

static PyObject *
gmsslext_sm2_encrypt(PyObject *self, PyObject *args, PyObject *keywds) {
    SM2_KEY sm2_key;
    const char *public_key;
    Py_ssize_t key_length;
    const char *plaintext;
    Py_ssize_t text_length;
    unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
    Py_ssize_t outlen;
    static char *kwlist[] = {"public_key", "plaintext", NULL};
    int ret;

    // sm2_encrypt(public_key: bytes, plaintext: bytes) -> bytes
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "y#y#", kwlist, &public_key, &key_length, &plaintext,
                                     &text_length)) {
        return NULL;
    }
    if (key_length != 64) {
        PyErr_SetString(InvalidValueError, "invalid public key length");
        return NULL;
    }
    if (text_length < SM2_MIN_PLAINTEXT_SIZE || text_length > SM2_MAX_PLAINTEXT_SIZE) {
        PyErr_SetString(InvalidValueError, "plaintext length not support");
        return NULL;
    }
    ret = sm2_key_set_public_key(&sm2_key, (SM2_POINT *) public_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "invalid public key");
        return NULL;
    }
    ret = sm2_encrypt(&sm2_key, (uint8_t *) plaintext, text_length, ciphertext, (size_t *) &outlen);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_encrypt");
        return NULL;
    }
    return Py_BuildValue("y#", ciphertext, outlen);
}

static PyObject *
gmsslext_sm2_decrypt(PyObject *self, PyObject *args, PyObject *keywds) {
    SM2_KEY sm2_key;
    const char *private_key;
    Py_ssize_t key_length;
    const char *ciphertext;
    Py_ssize_t text_length;
    unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
    Py_ssize_t outlen;
    static char *kwlist[] = {"private_key", "ciphertext", NULL};
    int ret;

    // sm2_decrypt(private_key: bytes, ciphertext: bytes) -> bytes
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "y#y#", kwlist, &private_key, &key_length, &ciphertext,
                                     &text_length)) {
        return NULL;
    }
    if (key_length != 32) {
        PyErr_SetString(InvalidValueError, "invalid private key length");
        return NULL;
    }
    if (text_length < SM2_MIN_CIPHERTEXT_SIZE || text_length > SM2_MAX_CIPHERTEXT_SIZE) {
        PyErr_SetString(InvalidValueError, "ciphertext length not support");
        return NULL;
    }
    ret = sm2_key_set_private_key(&sm2_key, (uint8_t *) private_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "invalid private key");
        return NULL;
    }
    ret = sm2_decrypt(&sm2_key, (uint8_t *) ciphertext, text_length, plaintext, (size_t *) &outlen);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_decrypt");
        return NULL;
    }
    return Py_BuildValue("y#", plaintext, outlen);
}

static PyObject *
gmsslext_sm2_sign_sm3_digest(PyObject *self, PyObject *args, PyObject *keywds) {
    SM2_KEY sm2_key;
    const char *private_key;
    Py_ssize_t key_length;
    const char *digest;
    Py_ssize_t digest_length;
    unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
    Py_ssize_t siglen;
    static char *kwlist[] = {"private_key", "digest", NULL};
    int ret;

    // sm2_sign_sm3_digest(private_key: bytes, digest: bytes) -> bytes
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "y#y#", kwlist, &private_key, &key_length, &digest,
                                     &digest_length)) {
        return NULL;
    }
    if (key_length != 32) {
        PyErr_SetString(InvalidValueError, "invalid private key length");
        return NULL;
    }
    if (digest_length != SM3_DIGEST_SIZE) {
        PyErr_SetString(InvalidValueError, "expected 32bytes sm3 digest");
        return NULL;
    }
    ret = sm2_key_set_private_key(&sm2_key, (uint8_t *) private_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "invalid private key");
        return NULL;
    }
    ret = sm2_sign(&sm2_key, (uint8_t *) digest, sig, (size_t *) &siglen);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_sign");
        return NULL;
    }
    return Py_BuildValue("y#", sig, siglen);
}

static PyObject *
gmsslext_sm2_verify_sm3_digest(PyObject *self, PyObject *args, PyObject *keywds) {
    SM2_KEY sm2_key;
    const char *public_key;
    Py_ssize_t key_length;
    const char *digest;
    Py_ssize_t digest_length;
    const char *sig;
    Py_ssize_t siglen;
    static char *kwlist[] = {"public_key", "digest", "signature", NULL};
    int ret;

    // sm2_verify_sm3_digest(public_key: bytes, digest: bytes, signature: bytes) -> bool
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "y#y#y#", kwlist, &public_key, &key_length, &digest, &digest_length,
                                     &sig, &siglen)) {
        return NULL;
    }
    if (key_length != 64) {
        PyErr_SetString(InvalidValueError, "invalid public key length");
        return NULL;
    }
    if (digest_length != SM3_DIGEST_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm3 digest");
        return NULL;
    }
    ret = sm2_key_set_public_key(&sm2_key, (SM2_POINT *) public_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "invalid public key");
        return NULL;
    }
    ret = sm2_verify(&sm2_key, (uint8_t *) digest, (uint8_t *) sig, siglen);
    if (ret == 1) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *
gmsslext_sm2_sign(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *private_key;
    Py_ssize_t private_key_length;
    const char *public_key;
    Py_ssize_t public_key_length;
    const char *message;
    Py_ssize_t message_length;
    PyObject *signer_id_obj = NULL;
    int ret, ok;
    static char *kwlist[] = {"private_key", "public_key", "message", "signer_id", NULL};

    // sm2_sign(private_key: bytes, public_key: bytes, message: bytes, signer_id: t.Optional[bytes] = b'1234567812345678') -> bytes:
    ok = PyArg_ParseTupleAndKeywords(
            args,
            keywds,
            "y#y#y#|O",
            kwlist,
            &private_key, &private_key_length,
            &public_key, &public_key_length,
            &message, &message_length,
            &signer_id_obj);
    if (!ok) {
        return NULL;
    }
    const char *signer_id = NULL;
    size_t signer_id_length = 0;
    if (signer_id_obj == NULL) {
        // 没有传 signer_id ，使用默认值
        signer_id = SM2_DEFAULT_ID;
        signer_id_length = SM2_DEFAULT_ID_LENGTH;
    } else if (signer_id_obj != Py_None) {
        // 参数 signer_id 传的值不是 None
        signer_id = PyBytes_AsString(signer_id_obj);
        if (signer_id == NULL) {
            PyErr_SetString(InvalidValueError, "invalid signer_id");
            return NULL;
        }
        signer_id_length = PyBytes_Size(signer_id_obj);
    }
    if (public_key_length != 64 || private_key_length != 32) {
        PyErr_SetString(InvalidValueError, "invalid public_key or private_key");
        return NULL;
    }

    SM2_KEY sm2_key;
    SM2_SIGN_CTX sign_ctx;
    ret = sm2_key_set_public_key(&sm2_key, (SM2_POINT *) public_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "invalid public_key");
        return NULL;
    }
    ret = sm2_key_set_private_key(&sm2_key, (uint8_t *) private_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "invalid private_key");
        return NULL;
    }
    ret = sm2_sign_init(&sign_ctx, &sm2_key, signer_id, signer_id_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_sign_init");
        return NULL;
    }
    ret = sm2_sign_update(&sign_ctx, (uint8_t *) message, message_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_sign_update");
        return NULL;
    }
    unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
    Py_ssize_t siglen;
    ret = sm2_sign_finish(&sign_ctx, sig, (size_t *) &siglen);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_sign_finish");
        return NULL;
    }
    return Py_BuildValue("y#", sig, siglen);
}

static PyObject *
gmsslext_sm2_verify(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *private_key;
    Py_ssize_t private_key_length;
    const char *public_key;
    Py_ssize_t public_key_length;
    const char *message;
    Py_ssize_t message_length;
    const char *signature;
    Py_ssize_t signature_length;
    PyObject *signer_id_obj = NULL;
    static char *kwlist[] = {"private_key", "public_key", "message", "signature", "signer_id", NULL};
    int ret, ok;

    //  sm2_verify(
    //      private_key: bytes, public_key: bytes,
    //      message: bytes, signature: bytes,
    //      signer_id: t.Optional[bytes] = b'1234567812345678') -> bool
    ok = PyArg_ParseTupleAndKeywords(
            args,
            keywds,
            "y#y#y#y#|O",
            kwlist,
            &private_key, &private_key_length,
            &public_key, &public_key_length,
            &message, &message_length,
            &signature, &signature_length,
            &signer_id_obj);
    if (!ok) {
        return NULL;
    }
    const char *signer_id = NULL;
    Py_ssize_t signer_id_length = 0;
    if (signer_id_obj == NULL) {
        // 没有传 signer_id ，使用默认值
        signer_id = SM2_DEFAULT_ID;
        signer_id_length = SM2_DEFAULT_ID_LENGTH;
    } else if (signer_id_obj != Py_None) {
        // 参数 signer_id 传的值不是 None
        signer_id = PyBytes_AsString(signer_id_obj);
        if (signer_id == NULL) {
            PyErr_SetString(InvalidValueError, "invalid signer_id");
            return NULL;
        }
        signer_id_length = PyBytes_Size(signer_id_obj);
    }
    if (public_key_length != 64 || private_key_length != 32) {
        PyErr_SetString(InvalidValueError, "invalid public_key or private_key");
        return NULL;
    }

    SM2_KEY sm2_key;
    SM2_SIGN_CTX sign_ctx;
    ret = sm2_key_set_public_key(&sm2_key, (SM2_POINT *) public_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "invalid public_key");
        return NULL;
    }
    ret = sm2_key_set_private_key(&sm2_key, (uint8_t *) private_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "invalid private_key");
        return NULL;
    }
    ret = sm2_verify_init(&sign_ctx, &sm2_key, signer_id, signer_id_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_verify_init");
        return NULL;
    }
    ret = sm2_verify_update(&sign_ctx, (uint8_t *) message, message_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm2_verify_update");
        return NULL;
    }
    ret = sm2_verify_finish(&sign_ctx, (uint8_t *) signature, signature_length);
    if (ret == 1) {
        Py_RETURN_TRUE;
    } else {
        Py_RETURN_FALSE;
    }
}

static PyObject *
gmsslext_sm3_hash(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *message;
    Py_ssize_t message_length;
    int ok;

    static char *kwlist[] = {"message", NULL};
    // sm3_hash(message: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "y#", kwlist, &message, &message_length);
    if (!ok) {
        return NULL;
    }
    SM3_CTX sm3_ctx;
    uint8_t digest[32];
    sm3_init(&sm3_ctx);
    sm3_update(&sm3_ctx, (uint8_t *) message, message_length);
    sm3_finish(&sm3_ctx, digest);
    return Py_BuildValue("y#", digest, (Py_ssize_t) 32);
}

static PyObject *
gmsslext_sm3_hmac(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *message;
    Py_ssize_t message_length;
    const char *key;
    Py_ssize_t key_length;
    int ok;

    static char *kwlist[] = {"key", "message", NULL};
    // sm3_hmac(key: bytes, message: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(
            args, keywds, "y#y#", kwlist,
            &key, &key_length,
            &message, &message_length);
    if (!ok) {
        return NULL;
    }
    SM3_HMAC_CTX hmac_ctx;
    uint8_t digest[SM3_HMAC_SIZE];
    sm3_hmac_init(&hmac_ctx, (uint8_t *) key, key_length);
    sm3_hmac_update(&hmac_ctx, (uint8_t *) message, message_length);
    sm3_hmac_finish(&hmac_ctx, digest);
    return Py_BuildValue("y#", digest, (Py_ssize_t) SM3_HMAC_SIZE);
}

static PyObject *
gmsslext_sm3_kdf(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *key;
    Py_ssize_t key_length;
    unsigned long outlen;
    int ok;

    static char *kwlist[] = {"key", "outlen", NULL};
    // sm3_kdf(key: bytes, outlen: int) -> bytes
    ok = PyArg_ParseTupleAndKeywords(
            args, keywds, "y#k", kwlist,
            &key, &key_length,
            &outlen);
    if (!ok) {
        return NULL;
    }
    char *out = PyMem_RawMalloc(outlen);
    if (out == NULL) {
        return PyErr_NoMemory();
    }
    SM3_KDF_CTX kdf_ctx;
    sm3_kdf_init(&kdf_ctx, outlen);
    sm3_kdf_update(&kdf_ctx, (uint8_t *) key, key_length);
    sm3_kdf_finish(&kdf_ctx, (uint8_t *) out);
    PyObject *new_key = Py_BuildValue("y#", out, (Py_ssize_t) outlen);
    PyMem_RawFree(out);
    return new_key;
}

static PyObject *
gmsslext_sm4_cbc_padding_encrypt(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *key;
    Py_ssize_t key_length;
    const char *iv;
    Py_ssize_t iv_length;
    const char *plaintext;
    Py_ssize_t plaintext_length;
    int ok;
    static char *kwlist[] = {"key", "iv", "plaintext", NULL};
    // sm4_cbc_pading_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(
            args,
            keywds,
            "y#y#y#",
            kwlist,
            &key, &key_length,
            &iv, &iv_length,
            &plaintext, &plaintext_length);
    if (!ok) {
        return NULL;
    }
    if (key_length != SM4_KEY_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 key length");
        return NULL;
    }
    if (iv_length != SM4_BLOCK_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 iv length");
        return NULL;
    }
    SM4_KEY sm4_key;
    // 后面最多填充 SM4_BLOCK_SIZE 个字节
    Py_ssize_t outlen = plaintext_length + SM4_BLOCK_SIZE;
    char *out = PyMem_RawMalloc(outlen);
    if (out == NULL) {
        return PyErr_NoMemory();
    }
    sm4_set_encrypt_key(&sm4_key, (uint8_t *) key);
    sm4_cbc_padding_encrypt(
            &sm4_key, (uint8_t *) iv,
            (uint8_t *) plaintext, plaintext_length,
            (uint8_t *) out, (size_t *) &outlen);
    PyObject *ciphertext_obj = Py_BuildValue("y#", out, outlen);
    PyMem_RawFree(out);
    return ciphertext_obj;
}

static PyObject *
gmsslext_sm4_cbc_padding_decrypt(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *key;
    Py_ssize_t key_length;
    const char *iv;
    Py_ssize_t iv_length;
    const char *ciphertext;
    Py_ssize_t ciphertext_length;
    int ok;
    static char *kwlist[] = {"key", "iv", "ciphertext", NULL};
    // sm4_cbc_pading_encrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(
            args,
            keywds,
            "y#y#y#",
            kwlist,
            &key, &key_length,
            &iv, &iv_length,
            &ciphertext, &ciphertext_length);
    if (!ok) {
        return NULL;
    }
    if (key_length != SM4_KEY_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 key length");
        return NULL;
    }
    if (iv_length != SM4_BLOCK_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 iv length");
        return NULL;
    }
    SM4_KEY sm4_key;
    // 后面最多填充 SM4_BLOCK_SIZE 个字节
    Py_ssize_t outlen = ciphertext_length;
    char *out = PyMem_RawMalloc(outlen);
    if (out == NULL) {
        return PyErr_NoMemory();
    }
    sm4_set_decrypt_key(&sm4_key, (uint8_t *) key);
    sm4_cbc_padding_decrypt(
            &sm4_key, (uint8_t *) iv,
            (uint8_t *) ciphertext, ciphertext_length,
            (uint8_t *) out, (size_t *) &outlen);
    PyObject *plaintext_obj = Py_BuildValue("y#", out, outlen);
    PyMem_RawFree(out);
    return plaintext_obj;
}

static PyObject *
gmsslext_sm4_ctr_encrypt(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *key;
    Py_ssize_t key_length;
    const char *ctr;
    Py_ssize_t ctr_length;
    const char *plaintext;
    Py_ssize_t plaintext_length;
    int ok;
    static char *kwlist[] = {"key", "ctr", "plaintext", NULL};
    // sm4_ctr_encrypt(key: bytes, ctr: bytes, plaintext: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(
            args,
            keywds,
            "y#y#y#",
            kwlist,
            &key, &key_length,
            &ctr, &ctr_length,
            &plaintext, &plaintext_length);
    if (!ok) {
        return NULL;
    }
    if (key_length != SM4_KEY_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 key length");
        return NULL;
    }
    if (ctr_length != SM4_BLOCK_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 ctr length");
        return NULL;
    }
    SM4_KEY sm4_key;
    // 密文长度与明文一致
    char *out = PyMem_RawMalloc(plaintext_length);
    if (out == NULL) {
        return PyErr_NoMemory();
    }
    sm4_set_encrypt_key(&sm4_key, (uint8_t *) key);
    // sm4_ctr_encrypt 会修改 ctr ，会导致 Python 端调用者的 ctr 也发生改变，copy 一份来用
    unsigned char temp_ctr[16];
    memcpy(temp_ctr, ctr, 16);
    sm4_ctr_encrypt(
            &sm4_key, temp_ctr,
            (uint8_t *) plaintext, plaintext_length,
            (uint8_t *) out);
    PyObject *ciphertext_obj = Py_BuildValue("y#", out, plaintext_length);
    PyMem_RawFree(out);
    return ciphertext_obj;
}

static PyObject *
gmsslext_sm4_ctr_decrypt(PyObject *self, PyObject *args, PyObject *keywds) {
    const char *key;
    Py_ssize_t key_length;
    const char *ctr;
    Py_ssize_t ctr_length;
    const char *ciphertext;
    Py_ssize_t ciphertext_length;
    int ok;
    static char *kwlist[] = {"key", "ctr", "ciphertext", NULL};
    // sm4_ctr_decrypt(key: bytes, ctr: bytes, ciphertext: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(
            args,
            keywds,
            "y#y#y#",
            kwlist,
            &key, &key_length,
            &ctr, &ctr_length,
            &ciphertext, &ciphertext_length);
    if (!ok) {
        return NULL;
    }
    if (key_length != SM4_KEY_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 key length");
        return NULL;
    }
    if (ctr_length != SM4_BLOCK_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 ctr length");
        return NULL;
    }

    SM4_KEY sm4_key;
    // 明文和密文长度一致
    char *out = PyMem_RawMalloc(ciphertext_length);
    if (out == NULL) {
        return PyErr_NoMemory();
    }
    sm4_set_encrypt_key(&sm4_key, (uint8_t *) key);

    // sm4_ctr_decrypt 会修改 ctr ，会导致 Python 端调用者的 ctr 也发生改变，copy 一份来用
    unsigned char temp_ctr[16];
    memcpy(temp_ctr, ctr, 16);
    sm4_ctr_decrypt(
            &sm4_key, temp_ctr,
            (uint8_t *) ciphertext, ciphertext_length,
            (uint8_t *) out);
    PyObject *plaintext_obj = Py_BuildValue("y#", out, ciphertext_length);
    PyMem_RawFree(out);
    return plaintext_obj;
}

static PyObject *
gmsslext_sm4_gcm_encrypt(PyObject *self, PyObject *args, PyObject *keywds) {
    int ok;
    const char *key;
    Py_ssize_t key_length;
    const char *iv;
    Py_ssize_t iv_length;
    const char *aad;
    Py_ssize_t aad_length;
    const char *plaintext;
    Py_ssize_t plaintext_length;
    static char *kwlist[] = {"key", "iv", "aad", "plaintext", NULL};
    // sm4_gcm_encrypt(key: bytes, iv: bytes, aad: bytes, plaintext: bytes) -> t.Tuple[bytes, bytes]
    ok = PyArg_ParseTupleAndKeywords(
            args,
            keywds,
            "y#y#y#y#",
            kwlist,
            &key, &key_length,
            &iv, &iv_length,
            &aad, &aad_length,
            &plaintext, &plaintext_length);
    if (!ok) {
        return NULL;
    }
    if (key_length != SM4_KEY_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 key length");
        return NULL;
    }
    SM4_KEY sm4_key;
    char tag[16];
    // 密文长度与明文一致
    char *out = PyMem_RawMalloc(plaintext_length);
    if (out == NULL) {
        return PyErr_NoMemory();
    }
    sm4_set_encrypt_key(&sm4_key, (uint8_t *) key);
    int ret = sm4_gcm_encrypt(
            &sm4_key,
            (uint8_t *) iv, iv_length,
            (uint8_t *) aad, aad_length,
            (uint8_t *) plaintext, plaintext_length,
            (uint8_t *) out, sizeof(tag), (uint8_t *) tag);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "libgmssl inner error in sm4_gcm_encrypt");
        return NULL;
    }
    PyObject *obj = Py_BuildValue("y#y#", out, plaintext_length, tag, (Py_ssize_t) 16);
    PyMem_RawFree(out);
    return obj;
}

static PyObject *
gmsslext_sm4_gcm_decrypt(PyObject *self, PyObject *args, PyObject *keywds) {
    int ok;
    const char *key;
    Py_ssize_t key_length;
    const char *iv;
    Py_ssize_t iv_length;
    const char *aad;
    Py_ssize_t aad_length;
    const char *ciphertext;
    Py_ssize_t ciphertext_length;
    const char *tag;
    Py_ssize_t tag_length;
    static char *kwlist[] = {"key", "iv", "aad", "ciphertext", "tag", NULL};
    // sm4_gcm_decrypt(key: bytes, iv: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(
            args,
            keywds,
            "y#y#y#y#y#",
            kwlist,
            &key, &key_length,
            &iv, &iv_length,
            &aad, &aad_length,
            &ciphertext, &ciphertext_length,
            &tag, &tag_length);
    if (!ok) {
        return NULL;
    }
    if (key_length != SM4_KEY_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm4 key length");
        return NULL;
    }
    SM4_KEY sm4_key;
    // 密文长度与明文一致
    char *out = PyMem_RawMalloc(ciphertext_length);
    if (out == NULL) {
        return PyErr_NoMemory();
    }
    sm4_set_encrypt_key(&sm4_key, (uint8_t *) key);
    int ret = sm4_gcm_decrypt(
            &sm4_key,
            (uint8_t *) iv, iv_length,
            (uint8_t *) aad, aad_length,
            (uint8_t *) ciphertext, ciphertext_length,
            (uint8_t *) tag, tag_length, (uint8_t *) out);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidValueError, "libgmssl inner error in sm4_gcm_decrypt");
        return NULL;
    }
    PyObject *obj = Py_BuildValue("y#", out, ciphertext_length);
    PyMem_RawFree(out);
    return obj;
}


// 定义模块暴露的函数
static PyMethodDef SpamMethods[] = {
        {
                "sm2_key_generate",
                gmsslext_sm2_key_generate,
                METH_VARARGS,
                "生成 SM2 公私密钥对",
        },
        {
                "sm2_encrypt",
                (PyCFunction) (void (*)(void)) gmsslext_sm2_encrypt,
                METH_VARARGS | METH_KEYWORDS,

                        "SM2 公钥加密",
        },
        {
                "sm2_decrypt",
                (PyCFunction) (void (*)(void)) gmsslext_sm2_decrypt,
                METH_VARARGS | METH_KEYWORDS,
                        "SM2 私钥解密",
        },
        {
                "sm2_sign_sm3_digest",
                (PyCFunction) (void (*)(void)) gmsslext_sm2_sign_sm3_digest,
                METH_VARARGS | METH_KEYWORDS,
                        "SM2 签名 SM3 摘要",
        },
        {
                "sm2_verify_sm3_digest",
                (PyCFunction) (void (*)(void)) gmsslext_sm2_verify_sm3_digest,
                METH_VARARGS | METH_KEYWORDS,
                        "SM2 验证 SM3 摘要和签名",
        },
        {
                "sm2_sign",
                (PyCFunction) (void (*)(void)) gmsslext_sm2_sign,
                METH_VARARGS | METH_KEYWORDS,
                        "SM2 签名",
        },
        {
                "sm2_verify",
                (PyCFunction) (void (*)(void)) gmsslext_sm2_verify,
                METH_VARARGS | METH_KEYWORDS,
                        "SM2 验证签名",
        },
        {
                "sm3_hash",
                (PyCFunction) (void (*)(void)) gmsslext_sm3_hash,
                METH_VARARGS | METH_KEYWORDS,
                        "SM3 hash",
        },
        {
                "sm3_hmac",
                (PyCFunction) (void (*)(void)) gmsslext_sm3_hmac,
                METH_VARARGS | METH_KEYWORDS,
                        "SM3 hmac",
        },
        {
                "sm3_kdf",
                (PyCFunction) (void (*)(void)) gmsslext_sm3_kdf,
                METH_VARARGS | METH_KEYWORDS,
                        "SM3 kdf",
        },
        {
                "sm4_cbc_padding_encrypt",
                (PyCFunction) (void (*)(void)) gmsslext_sm4_cbc_padding_encrypt,
                METH_VARARGS | METH_KEYWORDS,
                        "SM3 cbc encrypt, use PKCS#7 padding",
        },
        {
                "sm4_cbc_padding_decrypt",
                (PyCFunction) (void (*)(void)) gmsslext_sm4_cbc_padding_decrypt,
                METH_VARARGS | METH_KEYWORDS,
                        "SM3 cbc decrypt, use PKCS#7 padding",
        },
        {
                "sm4_ctr_encrypt",
                (PyCFunction) (void (*)(void)) gmsslext_sm4_ctr_encrypt,
                METH_VARARGS | METH_KEYWORDS,
                        "SM3 ctr encrypt",
        },
        {
                "sm4_ctr_decrypt",
                (PyCFunction) (void (*)(void)) gmsslext_sm4_ctr_decrypt,
                METH_VARARGS | METH_KEYWORDS,
                        "SM3 ctr decrypt",
        },
        {
                "sm4_gcm_encrypt",
                (PyCFunction) (void (*)(void)) gmsslext_sm4_gcm_encrypt,
                METH_VARARGS | METH_KEYWORDS,
                "SM3 gcm encrypt",
        },
        {
                "sm4_gcm_decrypt",
                (PyCFunction) (void (*)(void)) gmsslext_sm4_gcm_decrypt,
                METH_VARARGS | METH_KEYWORDS,
                "SM3 gcm decrypt",
        },
        {NULL, NULL, 0, NULL}        /* Sentinel */
};

// 模块属性定义
static struct PyModuleDef spammodule = {
        PyModuleDef_HEAD_INIT,
        "gmsslext",   /* name of module */
        "gmsslext doc", /* module documentation, may be NULL */
        -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
        SpamMethods,
        NULL,
        NULL,
        NULL,
        NULL,
};

PyMODINIT_FUNC
PyInit_gmsslext(void) {
    PyObject *m;

    m = PyModule_Create(&spammodule);
    if (m == NULL)
        return NULL;

    // 新建异常 gmssl.GmsslInnerError ，父类为 Exception
    GmsslInnerError = PyErr_NewException("gmsslext.GmsslInnerError", NULL, NULL);
    Py_XINCREF(GmsslInnerError);
    if (PyModule_AddObject(m, "GmsslInnerError", GmsslInnerError) < 0) {
        Py_XDECREF(GmsslInnerError);
        Py_CLEAR(GmsslInnerError);
        Py_DECREF(m);
        return NULL;
    }
    // 新建异常 gmssl.InvalidValueError ，父类为 GmsslInnerError
    InvalidValueError = PyErr_NewException("gmsslext.InvalidValueError", GmsslInnerError, NULL);
    Py_XINCREF(InvalidValueError);
    if (PyModule_AddObject(m, "InvalidValueError", InvalidValueError) < 0) {
        Py_XDECREF(InvalidValueError);
        Py_CLEAR(InvalidValueError);
        Py_XDECREF(GmsslInnerError);
        Py_CLEAR(GmsslInnerError);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}

