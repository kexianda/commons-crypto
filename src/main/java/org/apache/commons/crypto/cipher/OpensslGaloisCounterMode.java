/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.commons.crypto.cipher;


import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * This class do the real work(Encryption/Decryption/Authentication) for GCM.
 *
 * It will call the OpenSSL API to implement JCE-like behavior
 *
 * @since 1.1
 */
class OpensslGaloisCounterMode extends OpensslBlockCipher{

    // buffer for AAD data; if consumed, set as null
    private ByteArrayOutputStream aadBuffer = new ByteArrayOutputStream();
    private int tagBitLen = -1;

    static final int DEFAULT_TAG_LEN = 16;

    // buffer for storing input in decryption, not used for encryption
    private ByteArrayOutputStream inBuffer = null;

    public OpensslGaloisCounterMode(long context, int algorithmMode, int padding) {
        super(context, algorithmMode, padding);
    }

    @Override
    public void init(int mode,  byte[] key, AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {

        this.cipherMode = mode;
        byte[] iv;
        if(params instanceof GCMParameterSpec) {
            GCMParameterSpec gcmParam = (GCMParameterSpec) params;
            iv = gcmParam.getIV();
            this.tagBitLen = gcmParam.getTLen();
        } else {
            // other AlgorithmParameterSpec is not supported now.
            throw new InvalidAlgorithmParameterException("Illegal parameters");
        }

        if (this.cipherMode == Openssl.DECRYPT_MODE) {
            inBuffer = new ByteArrayOutputStream();
        }

        context = OpensslNative.init(context, mode, algorithmMode, padding, key, iv);
    }

    @Override
    public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        processAAD();

        int len;
        if (this.cipherMode == Openssl.DECRYPT_MODE) {
            // store internally until doFinal(decrypt) is called because
            // spec mentioned that only return recovered data after tag
            // is successfully verified
            int inputLen = input.remaining();
            byte[] inputBuf = new byte[inputLen];
            input.get(inputBuf, 0, inputLen);
            inBuffer.write(inputBuf, 0, inputLen);
            return 0;
        } else {
            len = OpensslNative.update(context, input, input.position(),
                    input.remaining(), output, output.position(),
                    output.remaining());
            input.position(input.limit());
            output.position(output.position() + len);
        }

        return len;
    }

    @Override
    public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        processAAD();

        if (this.cipherMode == Openssl.DECRYPT_MODE) {
            // store internally until doFinal(decrypt) is called because
            // spec mentioned that only return recovered data after tag
            // is successfully verified
            inBuffer.write(input, inputOffset, inputLen);
            return 0;
        } else {
            return OpensslNative.updateByteArray(context, input, inputOffset,
                    inputLen, output, outputOffset, output.length - outputOffset);
        }
    }

    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        processAAD();

        int len;
        if (this.cipherMode == Openssl.DECRYPT_MODE) {
            // if GCM-DECRYPT, we have to handle the buffered input
            // and the retrieve the trailing tag from input
            int inputOffsetFinal = inputOffset;
            int inputLenFinal = inputLen;
            byte[] inputFinal;
            if (inBuffer != null && inBuffer.size() > 0) {
                inBuffer.write(input, inputOffset, inputLen);
                inputFinal = inBuffer.toByteArray();
                inputOffsetFinal = 0;
                inputLenFinal = inputFinal.length;
                inBuffer.reset();
            } else {
                inputFinal = input;
            }

            if (inputFinal.length < getTagLen()) {
                throw new AEADBadTagException("Input too short - need tag");
            }

            int inputDataLen = inputLenFinal  - getTagLen();
            len = OpensslNative.updateByteArray(context, inputFinal, inputOffsetFinal,
                    inputDataLen, output, outputOffset, output.length - outputOffset);

            // set tag to EVP_Cipher for integrity verification in doFinal
            ByteBuffer tag = ByteBuffer.allocate(getTagLen());
            tag.put(input, input.length - getTagLen(), getTagLen());
            tag.flip();
            evpCipherCtxCtrl(context, EvpCtrlValues.AEAD_SET_TAG.getValue(), getTagLen(), tag);
        } else {
            len = OpensslNative.updateByteArray(context, input, inputOffset,
                    inputLen, output, outputOffset, output.length - outputOffset);
        }

        len +=  OpensslNative.doFinalByteArray(context, output, outputOffset + len,
                output.length - outputOffset);

        // Keep the similar behavior as JCE, append the tag to end of output
        if(this.cipherMode == Openssl.ENCRYPT_MODE) {
            ByteBuffer tag;
            tag = ByteBuffer.allocate(getTagLen());
            evpCipherCtxCtrl(context, EvpCtrlValues.AEAD_GET_TAG.getValue(), getTagLen(), tag);
            tag.get(output, output.length-getTagLen(), getTagLen());
            len += getTagLen();
        }

        return len;
    }

    @Override
    public int doFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        processAAD();

        int totalLen = 0;
        int len;
        if (this.cipherMode == Openssl.DECRYPT_MODE) {
            // if GCM-DECRYPT, we have to handle the buffered input
            // and the retrieve the trailing tag from input
            if (inBuffer != null && inBuffer.size() > 0) {
                byte[] inputBytes = new byte[input.remaining()];
                input.get(inputBytes, 0, inputBytes.length);
                inBuffer.write(inputBytes, 0, inputBytes.length);
                byte[] inputFinal = inBuffer.toByteArray();
                inBuffer.reset();

                if (inputFinal.length < getTagLen()) {
                    throw new AEADBadTagException("Input too short - need tag");
                }

                len = OpensslNative.updateByteArrayByteBuffer(context, inputFinal, 0,
                        inputFinal.length - getTagLen(),
                        output, output.position(), output.remaining());
            } else {
                // if no buffered input, just use the input buffer
                if (input.remaining() < getTagLen()) {
                    throw new AEADBadTagException("Input too short - need tag");
                }

                len = OpensslNative.update(context, input, input.position(),
                        input.remaining() -  getTagLen(), output, output.position(),
                        output.remaining());

                input.position(input.position() + len);
            }

            // set tag to EVP_Cipher for integrity verification in doFinal
            ByteBuffer tag = ByteBuffer.allocate(getTagLen());
            tag.put(input);
            tag.flip();
            evpCipherCtxCtrl(context, EvpCtrlValues.AEAD_SET_TAG.getValue(),
                    getTagLen(), tag);
        } else {
            len = OpensslNative.update(context, input, input.position(),
                    input.remaining(), output, output.position(),
                    output.remaining());
            input.position(input.limit());
        }

        totalLen += len;
        output.position(output.position() + len);

        len = OpensslNative.doFinal(context, output, output.position(),
                output.remaining());
        output.position(output.position() + len);
        totalLen += len;

        // Keep the similar behavior as JCE, append the tag to end of output
        if (this.cipherMode == Openssl.ENCRYPT_MODE) {
            ByteBuffer tag;
            tag = ByteBuffer.allocate(getTagLen());
            evpCipherCtxCtrl(context, EvpCtrlValues.AEAD_GET_TAG.getValue(), getTagLen(), tag);
            output.put(tag);
            totalLen += getTagLen();
        }

        return totalLen;
    }

    @Override
    public void updateAAD(byte[] aad) {
        // must be called after initialized.
        if (aadBuffer != null) {
            aadBuffer.write(aad, 0, aad.length);
        } else {
            // update has already been called
            throw new IllegalStateException
                    ("Update has been called; no more AAD data");
        }
    }

    private void processAAD() {
        if (aadBuffer != null && aadBuffer.size() > 0) {
            OpensslNative.updateByteArray(context, aadBuffer.toByteArray(),
                    0, aadBuffer.size(), null, 0, 0);
            aadBuffer = null;
        }
    }

    private int getTagLen() {
        return tagBitLen < 0 ? DEFAULT_TAG_LEN : (tagBitLen >> 3);
    }

    /**
     * a wrapper of OpensslNative.ctrl(long context, int type, int arg, byte[] data)
     * Since native interface EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) is generic,
     * it may set/get any native char or long type to the data buffer(ptr).
     * Here we use ByteBuffer and set nativeOrder to handle the endianness.
     */
    public static void evpCipherCtxCtrl(long context, int type, int arg, ByteBuffer bb) {
        if (bb != null) {
            bb.order(ByteOrder.nativeOrder());
            OpensslNative.ctrl(context, type, arg, bb.array());
        } else {
            OpensslNative.ctrl(context, type, arg, null);
        }
    }
}
