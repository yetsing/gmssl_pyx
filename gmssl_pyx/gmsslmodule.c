/*
 * GmSSL sm2 python c extension
 */
#define PY_SSIZE_T_CLEAN

#include <Python.h>

#include "gmssl/sm2.h"

#define GMSSL_INNER_OK 1

static PyObject *GmsslInnerError;

static PyObject *InvalidKeyError;

static PyObject *InvalidArgumentError;

static PyObject *
gmsslext_sm2_key_generate(PyObject *self, PyObject *args) {
    SM2_KEY sm2_key;
    int ret, ok;

    // 函数没有参数
    ok = PyArg_ParseTuple(args, "");
    if (!ok) {
        return NULL;
    }
    ret = sm2_key_generate(&sm2_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error");
        return NULL;
    }
    // 整数字面量不是 Py_ssize_t 类型，需要强制转换，不然 Windows 会报错 MemoryError
    return Py_BuildValue("y#y#", &sm2_key.public_key, (Py_ssize_t) 64, &sm2_key.private_key, (Py_ssize_t) 32);
}

static PyObject *
gmsslext_sm2_encrypt(PyObject *self, PyObject *args) {
    SM2_KEY sm2_key;
    const char *public_key;
    Py_ssize_t key_length;
    const char *plaintext;
    Py_ssize_t text_length;
    unsigned char ciphertext[SM2_MAX_CIPHERTEXT_SIZE];
    Py_ssize_t outlen;
    int ret;

    if (!PyArg_ParseTuple(args, "y#y#", &public_key, &key_length, &plaintext, &text_length)) {
        return NULL;
    }
    if (key_length != 64) {
        PyErr_SetString(InvalidKeyError, "invalid public key length");
        return NULL;
    }
    if (text_length < SM2_MIN_PLAINTEXT_SIZE || text_length > SM2_MAX_PLAINTEXT_SIZE) {
        PyErr_SetString(GmsslInnerError, "plaintext length not support");
        return NULL;
    }
    ret = sm2_key_set_public_key(&sm2_key, (SM2_POINT *) public_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidKeyError, "invalid public key");
        return NULL;
    }
    ret = sm2_encrypt(&sm2_key, (uint8_t *) plaintext, text_length, ciphertext, (size_t *) &outlen);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error of sm2_encrypt");
        return NULL;
    }
    return Py_BuildValue("y#", ciphertext, outlen);
}

static PyObject *
gmsslext_sm2_decrypt(PyObject *self, PyObject *args) {
    SM2_KEY sm2_key;
    const char *private_key;
    Py_ssize_t key_length;
    const char *ciphertext;
    Py_ssize_t text_length;
    unsigned char plaintext[SM2_MAX_PLAINTEXT_SIZE];
    Py_ssize_t outlen;
    int ret;

    if (!PyArg_ParseTuple(args, "y#y#", &private_key, &key_length, &ciphertext, &text_length)) {
        return NULL;
    }
    if (key_length != 32) {
        PyErr_SetString(InvalidKeyError, "invalid private key length");
        return NULL;
    }
    if (text_length < SM2_MIN_CIPHERTEXT_SIZE || text_length > SM2_MAX_CIPHERTEXT_SIZE) {
        PyErr_SetString(GmsslInnerError, "ciphertext length not support");
        return NULL;
    }
    ret = sm2_key_set_private_key(&sm2_key, (uint8_t *) private_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidKeyError, "invalid private key");
        return NULL;
    }
    ret = sm2_decrypt(&sm2_key, (uint8_t *) ciphertext, text_length, plaintext, (size_t *) &outlen);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error of sm2_decrypt");
        return NULL;
    }
    return Py_BuildValue("y#", plaintext, outlen);
}

static PyObject *
gmsslext_sm2_sign_sm3_digest(PyObject *self, PyObject *args) {
    SM2_KEY sm2_key;
    const char *private_key;
    Py_ssize_t key_length;
    const char *digest;
    Py_ssize_t digest_length;
    unsigned char sig[SM2_MAX_SIGNATURE_SIZE];
    Py_ssize_t siglen;
    int ret;

    if (!PyArg_ParseTuple(args, "y#y#", &private_key, &key_length, &digest, &digest_length)) {
        return NULL;
    }
    if (key_length != 32) {
        PyErr_SetString(InvalidKeyError, "invalid private key length");
        return NULL;
    }
    if (digest_length != SM3_DIGEST_SIZE) {
        PyErr_SetString(InvalidArgumentError, "expected 32bytes sm3 digest");
        return NULL;
    }
    ret = sm2_key_set_private_key(&sm2_key, (uint8_t *) private_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidKeyError, "invalid private key");
        return NULL;
    }
    ret = sm2_sign(&sm2_key, digest, sig, &siglen);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error of sm2_sign");
        return NULL;
    }
    return Py_BuildValue("y#", sig, siglen);
}

static PyObject *
gmsslext_sm2_verify_sm3_digest(PyObject *self, PyObject *args) {
    SM2_KEY sm2_key;
    const char *public_key;
    Py_ssize_t key_length;
    const char *digest;
    Py_ssize_t digest_length;
    const char *sig;
    Py_ssize_t siglen;
    int ret;

    if (!PyArg_ParseTuple(args, "y#y#y#", &public_key, &key_length, &digest, &digest_length, &sig, &siglen)) {
        return NULL;
    }
    if (key_length != 64) {
        PyErr_SetString(InvalidKeyError, "invalid public key length");
        return NULL;
    }
    if (digest_length != SM3_DIGEST_SIZE) {
        PyErr_SetString(InvalidArgumentError, "invalid sm3 digest");
        return NULL;
    }
    ret = sm2_key_set_public_key(&sm2_key, (SM2_POINT *) public_key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(InvalidKeyError, "invalid public key");
        return NULL;
    }
    ret = sm2_verify(&sm2_key, digest, sig, siglen);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error of sm2_verify");
        return NULL;
    }
    return Py_BuildValue("y#", sig, siglen);
}

static PyObject *
spam_system(PyObject *self, PyObject *args) {
    const char *command;
    int sts;

    if (!PyArg_ParseTuple(args, "s", &command))
        return NULL;
    sts = system(command);
    if (sts < 0) {
        PyErr_SetString(GmsslInnerError, "System command failed");
        return NULL;
    }
    return PyLong_FromLong(sts);
}

// 定义模块暴露的函数
static PyMethodDef SpamMethods[] = {
        {"system", spam_system, METH_VARARGS,
         "Execute a shell command."},
        {"sm2_key_generate", gmsslext_sm2_key_generate, METH_VARARGS,
         "生成 SM2 公私密钥对"},
        {"sm2_encrypt", gmsslext_sm2_encrypt, METH_VARARGS,
         "使用 SM2 公钥加密"},
        {"sm2_decrypt", gmsslext_sm2_decrypt, METH_VARARGS,
         "使用 SM2 私钥解密"},
        {"sm2_sign_sm3_digest", gmsslext_sm2_sign_sm3_digest, METH_VARARGS,
         "使用 SM2 签名 SM3 摘要"},
        {"sm2_verify_sm3_digest", gmsslext_sm2_verify_sm3_digest, METH_VARARGS,
         "使用 SM2 验证 SM3 摘要和签名"},
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
    // 新建异常 gmssl.InvalidKeyError ，父类为 GmsslInnerError
    InvalidKeyError = PyErr_NewException("gmsslext.InvalidKeyError", GmsslInnerError, NULL);
    Py_XINCREF(InvalidKeyError);
    if (PyModule_AddObject(m, "InvalidKeyError", InvalidKeyError) < 0) {
        Py_XDECREF(InvalidKeyError);
        Py_CLEAR(InvalidKeyError);
        Py_XDECREF(GmsslInnerError);
        Py_CLEAR(GmsslInnerError);
        Py_DECREF(m);
        return NULL;
    }
    // 新建异常 gmssl.InvalidArgumentError ，父类为 GmsslInnerError
    InvalidArgumentError = PyErr_NewException("gmsslext.InvalidArgumentError", GmsslInnerError, NULL);
    Py_XINCREF(InvalidArgumentError);
    if (PyModule_AddObject(m, "InvalidArgumentError", InvalidArgumentError) < 0) {
        Py_XDECREF(InvalidArgumentError);
        Py_CLEAR(InvalidArgumentError);
        Py_XDECREF(InvalidKeyError);
        Py_CLEAR(InvalidKeyError);
        Py_XDECREF(GmsslInnerError);
        Py_CLEAR(GmsslInnerError);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}

