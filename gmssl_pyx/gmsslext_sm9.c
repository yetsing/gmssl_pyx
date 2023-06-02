//
// Created by yeqing on 23-5-2.
//
#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include "structmember.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "gmssl/sm9.h"

#include "gmsslext_sm9.h"
#include "gmsslext.h"

typedef struct {
    PyObject_HEAD
    PyObject *first; /* first name */
    PyObject *last;  /* last name */
    int number;
} CustomObject;

static void
Custom_dealloc(CustomObject *self) {
    Py_XDECREF(self->first);
    Py_XDECREF(self->last);
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
Custom_new(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    CustomObject *self;
    self = (CustomObject *) type->tp_alloc(type, 0);
    printf("new refcnt: %zd\n", self->ob_base.ob_refcnt);
    if (self != NULL) {
        self->first = PyUnicode_FromString("");
        if (self->first == NULL) {
            Py_DECREF(self);
            return NULL;
        }
        self->last = PyUnicode_FromString("");
        if (self->last == NULL) {
            Py_DECREF(self);
            return NULL;
        }
        self->number = 0;
    }
    return (PyObject *) self;
}

static int
Custom_init(CustomObject *self, PyObject *args, PyObject *keywds) {
    static char *kwlist[] = {"first", "last", "number", NULL};
    PyObject *first = NULL, *last = NULL, *tmp;

    if (!PyArg_ParseTupleAndKeywords(args, keywds, "|OOi", kwlist,
                                     &first, &last,
                                     &self->number))
        return -1;

    if (first) {
        tmp = self->first;
        Py_INCREF(first);
        self->first = first;
        Py_XDECREF(tmp);
    }
    if (last) {
        tmp = self->last;
        Py_INCREF(last);
        self->last = last;
        Py_XDECREF(tmp);
    }
    return 0;
}

static PyMemberDef Custom_members[] = {
        {"first",  T_OBJECT_EX, offsetof(CustomObject, first),  0,
                "first name"},
        {"last",   T_OBJECT_EX, offsetof(CustomObject, last),   0,
                "last name"},
        {"number", T_INT,       offsetof(CustomObject, number), 0,
                "custom number"},
        {NULL}  /* Sentinel */
};

static PyObject *
Custom_name(CustomObject *self, PyObject *Py_UNUSED(ignored)) {
    if (self->first == NULL) {
        PyErr_SetString(PyExc_AttributeError, "first");
        return NULL;
    }
    if (self->last == NULL) {
        PyErr_SetString(PyExc_AttributeError, "last");
        return NULL;
    }
    return PyUnicode_FromFormat("%S %S", self->first, self->last);
}

static PyMethodDef Custom_methods[] = {
        {"name", (PyCFunction) Custom_name, METH_NOARGS,
                "Return the name, combining the first and last name"
        },
        {NULL}  /* Sentinel */
};

PyTypeObject CustomType = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "gmsslext.Custom",
        .tp_doc = PyDoc_STR("Custom objects"),
        .tp_basicsize = sizeof(CustomObject),
        .tp_itemsize = 0,
        // 不用 Py_TPFLAGS_BASETYPE 是为了防止用户继承这个类
        .tp_flags = Py_TPFLAGS_DEFAULT,
        .tp_new = Custom_new,
        .tp_init = (initproc) Custom_init,
        .tp_dealloc = (destructor) Custom_dealloc,
        .tp_members = Custom_members,
        .tp_methods = Custom_methods,
};

/*
 * SM9 wrapper
 */

// SM9 private key
typedef struct {
    PyObject_HEAD
    SM9_ENC_KEY key;
} SM9PrivateKeyObject;

static void
SM9PrivateKey_dealloc(SM9PrivateKeyObject *self) {
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
SM9PrivateKey_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    SM9PrivateKeyObject *self;
    self = (SM9PrivateKeyObject *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

static int
SM9PrivateKey_init(SM9PrivateKeyObject *self, PyObject *args, PyObject *kwds) {
    static char *kwlist[] = {NULL};

    // 不接受任何参数
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist)) {
        return -1;
    }
    return 0;
}

static PyMemberDef SM9PrivateKey_members[] = {
        {NULL}  // 标记数组结束
};

static PyObject *
SM9PrivateKey_from_der(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    const char *data;
    Py_ssize_t data_length;
    static char *kwlist[] = {"data", NULL};
    int ret;

    // from_der(data: bytes) -> bytes
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "y#", kwlist, &data, &data_length)) {
        return NULL;
    }
    SM9PrivateKeyObject *self = (SM9PrivateKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }
    ret = sm9_enc_key_from_der(&self->key, (const uint8_t **) &data, &data_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_key_from_der");
        return NULL;
    }
    return (PyObject *) self;
}

static PyObject *
SM9PrivateKey_to_der(SM9PrivateKeyObject *self, PyObject *Py_UNUSED(ignored)) {
    // to_der(self) -> bytes
    uint8_t buf[512];
    uint8_t *p = buf;
    size_t len = 0;
    int ret;
    ret = sm9_enc_key_to_der(&self->key, &p, &len);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_key_to_der");
        return NULL;
    }
    return Py_BuildValue("y#", (char *) buf, (Py_ssize_t) len);
}

static PyObject *
SM9PrivateKey_decrypt_from_der(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    const char *data;
    Py_ssize_t data_length;
    const char *password;
    static char *kwlist[] = {"password", "data", NULL};
    int ret;

    // decrypt_from_der(cls, password: bytes, data: bytes) -> "SM9PrivateKey"
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "sy#", kwlist, &password, &data, &data_length)) {
        return NULL;
    }
    SM9PrivateKeyObject *self = (SM9PrivateKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }
    ret = sm9_enc_key_info_decrypt_from_der(&self->key, password, (const uint8_t **) &data, &data_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_key_info_decrypt_from_der");
        return NULL;
    }
    return (PyObject *) self;
}

static PyObject *
SM9PrivateKey_encrypt_to_der(SM9PrivateKeyObject *self, PyObject *args, PyObject *keywds) {
    const char *password;
    static char *kwlist[] = {"password", NULL};
    int ret;

    // encrypt_to_der(self, password: str) -> bytes
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &password)) {
        return NULL;
    }
    // code from sm9_enc_key_info_encrypt_to_pem
    uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
    uint8_t *p = buf;
    size_t len = 0;
    ret = sm9_enc_key_info_encrypt_to_der(&self->key, password, &p, &len);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_key_info_encrypt_to_der");
        return NULL;
    }
    return Py_BuildValue("y#", (char *) buf, (Py_ssize_t) len);
}

static PyObject *
SM9PrivateKey_decrypt_from_pem(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    const char *password;
    const char *filepath;
    static char *kwlist[] = {"password", "filepath", NULL};
    int ret;

    // decrypt_from_pem(cls, password: str, filepath: str) -> "SM9PrivateKey"
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ss", kwlist, &password, &filepath)) {
        return NULL;
    }
    SM9PrivateKeyObject *self = (SM9PrivateKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }
    FILE *fp = fopen(filepath, "r");
    if (fp == NULL) {
        PyErr_SetString(InvalidValueError, strerror(errno));
        return NULL;
    }
    ret = sm9_enc_key_info_decrypt_from_pem(&self->key, password, fp);
    if (ret != GMSSL_INNER_OK) {
        fclose(fp);
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_key_info_decrypt_from_pem");
        return NULL;
    }
    fclose(fp);
    return (PyObject *) self;
}

static PyObject *
SM9PrivateKey_encrypt_to_pem(SM9PrivateKeyObject *self, PyObject *args, PyObject *keywds) {
    const char *password;
    const char *filepath;
    static char *kwlist[] = {"password", "filepath", NULL};
    int ret;

    // decrypt_from_pem(cls, password: str, filepath: str) -> "SM9PrivateKey"
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "ss", kwlist, &password, &filepath)) {
        return NULL;
    }
    FILE *fp = fopen(filepath, "w");
    ret = sm9_enc_key_info_encrypt_to_pem(&self->key, password, fp);
    if (ret != GMSSL_INNER_OK) {
        fclose(fp);
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_key_info_encrypt_to_pem");
        return NULL;
    }
    fclose(fp);
    Py_RETURN_NONE;
}

static PyObject *
SM9PrivateKey_decrypt(SM9PrivateKeyObject *self, PyObject *args, PyObject *keywds) {
    int ok;
    const char *identity;
    Py_ssize_t identity_length;
    const char *ciphertext;
    Py_ssize_t ciphertext_length;
    static char *kwlist[] = {"identity", "ciphertext", NULL};
    // decrypt(self, identity: bytes, ciphertext: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "y#y#", kwlist, &identity, &identity_length, &ciphertext,
                                     &ciphertext_length);
    if (!ok) {
        return NULL;
    }
    if (ciphertext_length > SM9_MAX_CIPHERTEXT_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid sm9 ciphertext length.");
        return NULL;
    }

    int ret;
    char plaintext[SM9_MAX_PLAINTEXT_SIZE];
    Py_ssize_t plaintext_length;
    ret = sm9_decrypt(&self->key,
                      identity, identity_length,
                      (uint8_t *) ciphertext, ciphertext_length,
                      (uint8_t *) plaintext, &plaintext_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_decrypt");
        return NULL;
    }
    return Py_BuildValue("y#", plaintext, plaintext_length);
}

static PyMethodDef SM9PrivateKey_methods[] = {
        {
                "from_der",
                (PyCFunction) SM9PrivateKey_from_der,
                METH_CLASS | METH_VARARGS | METH_KEYWORDS,
                "sm9 private key from der",
        },
        {
                "to_der",
                (PyCFunction) SM9PrivateKey_to_der,
                METH_NOARGS,
                "sm9 private key to der",
        },
        {
                "decrypt_from_der",
                (PyCFunction) SM9PrivateKey_decrypt_from_der,
                METH_CLASS | METH_VARARGS | METH_KEYWORDS,
                "sm9 private key decrypt from der",
        },
        {
                "encrypt_to_der",
                (PyCFunction) SM9PrivateKey_encrypt_to_der,
                METH_VARARGS | METH_KEYWORDS,
                "sm9 private key encrypt to der",
        },
        {
                "decrypt_from_pem",
                (PyCFunction) SM9PrivateKey_decrypt_from_pem,
                METH_CLASS | METH_VARARGS | METH_KEYWORDS,
                "sm9 private key decrypt from pem",
        },
        {
                "encrypt_to_pem",
                (PyCFunction) SM9PrivateKey_encrypt_to_pem,
                METH_VARARGS | METH_KEYWORDS,
                "sm9 private key encrypt to pem",
        },
        {
                "decrypt",
                (PyCFunction) SM9PrivateKey_decrypt,
                METH_VARARGS | METH_KEYWORDS,
                "sm9 decrypt ciphertext",
        },
        {NULL}  // 标记数组结束
};

PyTypeObject GmsslextSM9PrivateKeyType = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "gmsslext.SM9PrivateKey",
        .tp_doc = PyDoc_STR("SM9PrivateKey objects"),
        .tp_basicsize = sizeof(SM9PrivateKeyObject),
        .tp_itemsize = 0,
        .tp_flags = Py_TPFLAGS_DEFAULT,
        .tp_new = SM9PrivateKey_new,
        .tp_init = (initproc) SM9PrivateKey_init,
        .tp_dealloc = (destructor) SM9PrivateKey_dealloc,
        .tp_members = SM9PrivateKey_members,
        .tp_methods = SM9PrivateKey_methods,
};

// SM9 master public key
typedef struct {
    PyObject_HEAD
    SM9_ENC_MASTER_KEY master_public;
} SM9MasterPublicKeyObject;

static void
SM9MasterPublicKey_dealloc(SM9MasterPublicKeyObject *self) {
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
SM9MasterPublicKey_new(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    SM9MasterPublicKeyObject *self;
    self = (SM9MasterPublicKeyObject *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

static int
SM9MasterPublicKey_init(SM9MasterPublicKeyObject *self, PyObject *args, PyObject *keywds) {
    int ok;
    static char *kwlist[] = {NULL};
    // 不接受任何参数
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "", kwlist);
    if (!ok) {
        return -1;
    }

    return 0;
}

static PyMemberDef SM9MasterPublicKey_members[] = {
        {NULL}  // 标记数组结束
};

static PyObject *
SM9MasterPublicKey_from_der(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    const char *data;
    Py_ssize_t data_length;
    static char *kwlist[] = {"data", NULL};
    int ret;

    // from_der(cls, data: bytes) -> "SM9MasterPublicKey"
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "y#", kwlist, &data, &data_length)) {
        return NULL;
    }
    SM9MasterPublicKeyObject *self = (SM9MasterPublicKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }
    ret = sm9_enc_master_public_key_from_der(&self->master_public, &data, &data_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_public_key_from_der");
        return NULL;
    }
    return (PyObject *) self;
}

static PyObject *
SM9MasterPublicKey_to_der(SM9MasterPublicKeyObject *self, PyObject *Py_UNUSED(ignored)) {
    // to_der(self) -> bytes
    uint8_t buf[1024];
    uint8_t *p = buf;
    size_t len = 0;
    int ret;
    ret = sm9_enc_master_public_key_to_der(&self->master_public, &p, &len);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_public_key_to_der");
        return NULL;
    }
    return Py_BuildValue("y#", (char *) buf, (Py_ssize_t) len);
}

static PyObject *
SM9MasterPublicKey_from_pem(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    const char *filepath;
    static char *kwlist[] = {"filepath", NULL};

    // from_pem(cls, filepath: str) -> "SM9MasterPublicKey"
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &filepath)) {
        return NULL;
    }
    SM9MasterPublicKeyObject *self = (SM9MasterPublicKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }

    FILE *fp = fopen(filepath, "r");
    if (fp == NULL) {
        PyErr_SetString(InvalidValueError, strerror(errno));
        return NULL;
    }
    int ret = sm9_enc_master_public_key_from_pem(&self->master_public, fp);
    if (ret != GMSSL_INNER_OK) {
        fclose(fp);
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_public_key_from_pem");
        return NULL;
    }
    fclose(fp);
    return (PyObject *) self;
}

static PyObject *
SM9MasterPublicKey_to_pem(SM9MasterPublicKeyObject *self, PyObject *args, PyObject *keywds) {
    const char *filepath;
    static char *kwlist[] = {"filepath", NULL};

    // to_pem(self, filepath: str) -> None
    if (!PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &filepath)) {
        return NULL;
    }
    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        PyErr_SetString(InvalidValueError, strerror(errno));
        return NULL;
    }
    int ret = sm9_enc_master_public_key_to_pem(&self->master_public, fp);
    if (ret != GMSSL_INNER_OK) {
        fclose(fp);
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_public_key_to_pem");
        return NULL;
    }
    fclose(fp);
    Py_RETURN_NONE;
}

static PyObject *
SM9MasterPublicKey_encrypt(SM9MasterPublicKeyObject *self, PyObject *args, PyObject *keywds) {
    static char *kwlist[] = {"identity", "plaintext", NULL};
    int ok;
    const char *identity;
    Py_ssize_t identity_length;
    const char *plaintext;
    Py_ssize_t plaintext_length;

    // encrypt(self, identity: bytes, plaintext: bytes) -> bytes
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "y#y#", kwlist, &identity, &identity_length, &plaintext,
                                     &plaintext_length);
    if (!ok) {
        return NULL;
    }

    if (plaintext_length > SM9_MAX_PLAINTEXT_SIZE) {
        PyErr_SetString(InvalidValueError, "invalid plaintext length");
        return NULL;
    }

    int ret;
    char ciphertext[SM9_MAX_CIPHERTEXT_SIZE];
    Py_ssize_t ciphertext_length;
    ret = sm9_encrypt(&self->master_public, identity, identity_length,
                      (uint8_t *) plaintext, plaintext_length,
                      (uint8_t *) ciphertext, &ciphertext_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_encrypt");
        return NULL;
    }
    return Py_BuildValue("y#", ciphertext, ciphertext_length);
}

static PyMethodDef SM9MasterPublicKey_methods[] = {
        {
                "from_der",
                (PyCFunction) SM9MasterPublicKey_from_der,
                METH_CLASS | METH_VARARGS | METH_KEYWORDS,
                "public key from der",
        },
        {
                "to_der",
                (PyCFunction) SM9MasterPublicKey_to_der,
                METH_NOARGS,
                "public key to der",
        },
        {
                "from_pem",
                (PyCFunction) SM9MasterPublicKey_from_pem,
                METH_CLASS | METH_VARARGS | METH_KEYWORDS,
                "public key from pem",
        },
        {
                "to_pem",
                (PyCFunction) SM9MasterPublicKey_to_pem,
                METH_VARARGS | METH_KEYWORDS,
                "public key to pem",
        },
        {
                "encrypt",
                (PyCFunction) SM9MasterPublicKey_encrypt,
                METH_VARARGS | METH_KEYWORDS,
                "sm9 encrypt",
        },
        {NULL}  // 标记数组结束
};

PyTypeObject GmsslextSM9MasterPublicKeyType = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "gmsslext.SM9MasterPublicKey",
        .tp_doc = PyDoc_STR("SM9MasterPublicKey objects, public key"),
        .tp_basicsize = sizeof(SM9MasterPublicKeyObject),
        .tp_itemsize = 0,
        // 不用 Py_TPFLAGS_BASETYPE 是为了防止用户继承这个类
        .tp_flags = Py_TPFLAGS_DEFAULT,
        .tp_new = SM9MasterPublicKey_new,
        .tp_init = (initproc) SM9MasterPublicKey_init,
        .tp_dealloc = (destructor) SM9MasterPublicKey_dealloc,
        .tp_members = SM9MasterPublicKey_members,
        .tp_methods = SM9MasterPublicKey_methods,
};


// SM9 master key
typedef struct {
    PyObject_HEAD
    SM9_ENC_MASTER_KEY master;
} SM9MasterKeyObject;

static void
SM9MasterKey_dealloc(SM9MasterKeyObject *self) {
    Py_TYPE(self)->tp_free((PyObject *) self);
}

static PyObject *
SM9MasterKey_new(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    SM9MasterKeyObject *self;
    self = (SM9MasterKeyObject *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

static int
SM9MasterKey_init(SM9MasterKeyObject *self, PyObject *args, PyObject *keywds) {
    int ok;
    static char *kwlist[] = {NULL};
    // 不接受任何参数
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "", kwlist);
    if (!ok) {
        return -1;
    }
    return 0;
}

// 定义类暴露的成员属性，可以使用 self.field 的形式， self 是类的实例
static PyMemberDef SM9MasterKey_members[] = {
        {NULL}  // 标记数组结束
};

static PyObject *
SM9MasterKey_generate(PyTypeObject *type, PyObject *Py_UNUSED(args)) {
    SM9MasterKeyObject *self = (SM9MasterKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }
    int ret = sm9_enc_master_key_generate(&self->master);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_key_generate");
        return NULL;
    }
    return (PyObject *) self;
}

static PyObject *
SM9MasterKey_from_der(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    int ok;
    static char *kwlist[] = {"data", NULL};
    const char *data;
    Py_ssize_t data_length;

    // from_der(cls, data: bytes) -> "SM9MasterKey"
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "y#", kwlist, &data, &data_length);
    if (!ok) {
        return NULL;
    }

    SM9MasterKeyObject *self = (SM9MasterKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }
    int ret = sm9_enc_master_key_from_der(&self->master, (const uint8_t **) &data, &data_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_key_from_der");
        return NULL;
    }
    return (PyObject *) self;
}

static PyObject *
SM9MasterKey_to_der(SM9MasterKeyObject *self, PyObject *Py_UNUSED(args)) {
    // to_der(self) -> bytes
    // code from sm9_enc_master_key_info_encrypt_to_der
    uint8_t buf[256];
    uint8_t *p = buf;
    size_t len = 0;
    int ret = sm9_enc_master_key_to_der(&self->master, &p, &len);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_key_to_der");
        return NULL;
    }
    // 这里不用 p ，因为 p 已经变了
    return Py_BuildValue("y#", buf, (Py_ssize_t) len);
}

static PyObject *
SM9MasterKey_decrypt_from_der(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    int ok;
    static char *kwlist[] = {"password", "data", NULL};
    const char *password;
    const char *data;
    Py_ssize_t data_length;
    // decrypt_from_der(cls, password: bytes, data: bytes) -> "SM9MasterKey"
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "sy#", kwlist, &password, &data, &data_length);
    if (!ok) {
        return NULL;
    }

    SM9MasterKeyObject *self = (SM9MasterKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }
    int ret = sm9_enc_master_key_info_decrypt_from_der(&self->master, password, (const uint8_t **) &data, &data_length);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_key_info_decrypt_from_der");
        return NULL;
    }
    return (PyObject *) self;
}

static PyObject *
SM9MasterKey_encrypt_to_der(SM9MasterKeyObject *self, PyObject *args, PyObject *keywds) {
    int ok;
    static char *kwlist[] = {"password", NULL};
    const char *password;
    // encrypt_to_der(self, password: str) -> bytes
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "s", kwlist, &password);
    if (!ok) {
        return NULL;
    }

    // code from sm9_enc_master_key_info_encrypt_to_pem
    uint8_t buf[SM9_MAX_ENCED_PRIVATE_KEY_INFO_SIZE];
    uint8_t *p = buf;
    size_t len = 0;
    int ret = sm9_enc_master_key_info_encrypt_to_der(&self->master, password, &p, &len);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_key_info_encrypt_to_der");
        return NULL;
    }
    // 这里不用 p ，因为 p 已经变了
    return Py_BuildValue("y#", buf, (Py_ssize_t) len);
}

static PyObject *
SM9MasterKey_decrypt_from_pem(PyTypeObject *type, PyObject *args, PyObject *keywds) {
    static char *kwlist[] = {"password", "filepath", NULL};
    const char *password;
    const char *filepath;
    // decrypt_from_pem(cls, password: str, filepath: str) -> "SM9MasterKey"
    int ok = PyArg_ParseTupleAndKeywords(args, keywds, "ss", kwlist, &password, &filepath);
    if (!ok) {
        return NULL;
    }

    SM9MasterKeyObject *self = (SM9MasterKeyObject *) PyObject_CallFunctionObjArgs((PyObject *) type, NULL);
    if (self == NULL) {
        return NULL;
    }
    FILE *fp = fopen(filepath, "r");
    if (fp == NULL) {
        PyErr_SetString(InvalidValueError, strerror(errno));
        return NULL;
    }
    int ret = sm9_enc_master_key_info_decrypt_from_pem(&self->master, password, fp);
    if (ret != GMSSL_INNER_OK) {
        fclose(fp);
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_key_info_decrypt_from_pem");
        return NULL;
    }
    fclose(fp);
    return (PyObject *) self;
}

static PyObject *
SM9MasterKey_encrypt_to_pem(SM9MasterKeyObject *self, PyObject *args, PyObject *keywds) {
    static char *kwlist[] = {"password", "filepath", NULL};
    const char *password;
    const char *filepath;
    // encrypt_to_pem(self, password: str, filepath: str) -> "SM9MasterKey"
    int ok = PyArg_ParseTupleAndKeywords(args, keywds, "ss", kwlist, &password, &filepath);
    if (!ok) {
        return NULL;
    }

    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        PyErr_SetString(InvalidValueError, strerror(errno));
        return NULL;
    }
    int ret = sm9_enc_master_key_info_encrypt_to_pem(&self->master, password, fp);
    if (ret != GMSSL_INNER_OK) {
        fclose(fp);
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_key_info_encrypt_to_pem");
        return NULL;
    }
    fclose(fp);
    Py_RETURN_NONE;
}

static PyObject *
SM9MasterKey_extract_key(SM9MasterKeyObject *self, PyObject *args, PyObject *keywds) {
    int ok;
    static char *kwlist[] = {"identity", NULL};
    const char *identity;
    Py_ssize_t identity_length;

    // extract_key(self, identity: bytes) -> "SM9PrivateKey"
    ok = PyArg_ParseTupleAndKeywords(args, keywds, "y#", kwlist, &identity, &identity_length);
    if (!ok) {
        return NULL;
    }

    SM9PrivateKeyObject *private_key;
    private_key = (SM9PrivateKeyObject *) PyObject_CallFunctionObjArgs(
            (PyObject *) &GmsslextSM9PrivateKeyType, NULL);
    if (private_key == NULL) {
        return NULL;
    }

    int ret;
    ret = sm9_enc_master_key_extract_key(&self->master, identity, identity_length, &private_key->key);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_key_extract_key");
        return NULL;
    }
    return (PyObject *) private_key;

}

static PyObject *
SM9MasterKey_public_key(SM9MasterKeyObject *self, PyObject *Py_UNUSED(ignored)) {
    // public_key(self) -> "SM9MasterPublicKey"
    uint8_t buf[512];
    uint8_t *p = buf;
    const uint8_t *cp = buf;
    size_t len = 0;
    int ret;
    ret = sm9_enc_master_public_key_to_der(&self->master, &p, &len);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_public_key_to_der");
        return NULL;
    }

    SM9MasterPublicKeyObject *public_key;
    public_key = (SM9MasterPublicKeyObject *) PyObject_CallFunctionObjArgs(
            (PyObject *) &GmsslextSM9MasterPublicKeyType, NULL);
    if (public_key == NULL) {
        return NULL;
    }

    ret = sm9_enc_master_public_key_from_der(&public_key->master_public, &cp, &len);
    if (ret != GMSSL_INNER_OK) {
        PyErr_SetString(GmsslInnerError, "libgmssl inner error in sm9_enc_master_public_key_from_der");
        return NULL;
    }

    return (PyObject *) public_key;
}

static PyMethodDef SM9MasterKey_methods[] = {
        {
                "generate",
                (PyCFunction) SM9MasterKey_generate,
                METH_NOARGS | METH_CLASS,
                "random master key",
        },
        {
                "from_der",
                (PyCFunction) SM9MasterKey_from_der,
                METH_CLASS | METH_VARARGS | METH_KEYWORDS,
                "master key from der",
        },
        {
                "to_der",
                (PyCFunction) SM9MasterKey_to_der,
                METH_NOARGS,
                "master key to der",
        },
        {
                "decrypt_from_der",
                (PyCFunction) SM9MasterKey_decrypt_from_der,
                METH_CLASS | METH_VARARGS | METH_KEYWORDS,
                "master key decrypt from der",
        },
        {
                "encrypt_to_der",
                (PyCFunction) SM9MasterKey_encrypt_to_der,
                METH_VARARGS | METH_KEYWORDS,
                "master key encrypt to der",
        },
        {
                "decrypt_from_pem",
                (PyCFunction) SM9MasterKey_decrypt_from_pem,
                METH_CLASS | METH_VARARGS | METH_KEYWORDS,
                "master key decrypt from pem",
        },
        {
                "encrypt_to_pem",
                (PyCFunction) SM9MasterKey_encrypt_to_pem,
                METH_VARARGS | METH_KEYWORDS,
                "master key encrypt to pem",
        },
        {
                "extract_key",
                (PyCFunction) SM9MasterKey_extract_key,
                METH_VARARGS | METH_KEYWORDS,
                "Get private key object by id",
        },
        {
                "public_key",
                (PyCFunction) SM9MasterKey_public_key,
                METH_NOARGS,
                "Get public key object",
        },
        {NULL}  // 标记数组结束
};

PyTypeObject GmsslextSM9MasterKeyType = {
        PyVarObject_HEAD_INIT(NULL, 0)
        .tp_name = "gmsslext.SM9MasterKey",
        .tp_doc = PyDoc_STR("SM9MasterKey objects, master key"),
        .tp_basicsize = sizeof(SM9MasterKeyObject),
        .tp_itemsize = 0,
        // 不用 Py_TPFLAGS_BASETYPE 是为了防止用户继承这个类
        .tp_flags = Py_TPFLAGS_DEFAULT,
        .tp_new = SM9MasterKey_new,
        .tp_init = (initproc) SM9MasterKey_init,
        .tp_dealloc = (destructor) SM9MasterKey_dealloc,
        .tp_members = SM9MasterKey_members,
        .tp_methods = SM9MasterKey_methods,
};

