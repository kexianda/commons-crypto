package org.apache.commons.crypto.cipher;

/**
 * This enum is defined for OpensslNative.ctrl() to allow various cipher
 * specific parameters to be determined and set.
 * see the macro definitions in openssl/evp.h
 */
enum EvpCtrlValues {
    INIT(0x00),
    SET_KEY_LENGTH(0x01),
    GET_RC2_KEY_BITS(0x02),
    SET_RC2_KEY_BITS(0x03),
    GET_RC5_ROUNDS(0x04),
    SET_RC5_ROUNDS(0x05),
    RAND_KEY(0x06),
    PBE_PRF_NID(0x07),
    COPY(0x08),
    AEAD_SET_IVLEN(0x09),
    AEAD_GET_TAG(0x10),
    AEAD_SET_TAG(0x11),
    AEAD_SET_IV_FIXED(0x12),
    GCM_IV_GEN(0x13),
    CCM_SET_L(0x14),
    CCM_SET_MSGLEN(0x15);

    private final int value;

    EvpCtrlValues(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
