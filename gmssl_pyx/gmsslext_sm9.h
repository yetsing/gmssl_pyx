#ifndef GMSSL_PYX_GMSSLEXT_SM9_H
#define GMSSL_PYX_GMSSLEXT_SM9_H

#include <Python.h>

extern PyTypeObject GmsslextSM9PrivateKeyType;
extern PyTypeObject GmsslextSM9MasterPublicKeyType;
extern PyTypeObject GmsslextSM9MasterKeyType;

#define PEM_SM9_ENC_MASTER_KEY_V3_1_1		"ENCRYPTED SM9 ENC MASTER KEY"
#define PEM_SM9_ENC_PRIVATE_KEY_V3_1_1		"ENCRYPTED SM9 ENC PRIVATE KEY"

#endif // GMSSL_PYX_GMSSLEXT_SM9_H
