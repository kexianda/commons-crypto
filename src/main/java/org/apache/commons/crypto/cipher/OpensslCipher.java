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

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Properties;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.crypto.utils.Utils;

/**
 * Implements the CryptoCipher using JNI into OpenSSL.
 */
public class OpensslCipher implements CryptoCipher {
    private final Properties props;
    private final CipherTransformation transformation;
    private final Openssl cipher;


    private boolean initialized = false;

    /**
     * Constructs a {@link CryptoCipher} using JNI into OpenSSL
     *
     * @param props properties for OpenSSL cipher
     * @param transformation transformation for OpenSSL cipher
     * @throws GeneralSecurityException if OpenSSL cipher initialize failed
     */
    public OpensslCipher(Properties props, CipherTransformation transformation)
            throws GeneralSecurityException {
        this.props = props;
        this.transformation = transformation;

        String loadingFailureReason = Openssl.getLoadingFailureReason();
        if (loadingFailureReason != null) {
            throw new RuntimeException(loadingFailureReason);
        }

        cipher = Openssl.getInstance(transformation.getName());
    }

    /**
     * Gets the CipherTransformation for the openssl cipher.
     *
     * @return the CipherTransformation for this cipher
     */
    @Override
    public CipherTransformation getTransformation() {
        return transformation;
    }

    /**
     * Gets the properties for the openssl cipher.
     *
     * @return the properties for this cipher.
     */
    @Override
    public Properties getProperties() {
        return props;
    }

    /**
     * Initializes the cipher with mode, key and iv.
     *
     * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
     * @param key crypto key for the cipher
     * @param params the algorithm parameters
     * @throws InvalidKeyException If key length is invalid
     * @throws InvalidAlgorithmParameterException if IV length is wrong
     */
    @Override
    public void init(int mode, Key key, AlgorithmParameterSpec params)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        Utils.checkNotNull(key);
        Utils.checkNotNull(params);

        int cipherMode = Openssl.DECRYPT_MODE;
        if (mode == ENCRYPT_MODE) {
            cipherMode = Openssl.ENCRYPT_MODE;
        }

        cipher.init(cipherMode, key.getEncoded(), params);
        initialized = true;
    }

    /**
     * Continues a multiple-part encryption/decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param inBuffer the input ByteBuffer
     * @param outBuffer the output ByteBuffer
     * @return int number of bytes stored in <code>output</code>
     * @throws ShortBufferException if there is insufficient space in the output
     *         buffer
     */
    @Override
    public int update(ByteBuffer inBuffer, ByteBuffer outBuffer)
            throws ShortBufferException {
        return cipher.update(inBuffer, outBuffer);
    }

    /**
     * Continues a multiple-part encryption/decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     *
     * @param input the input byte array
     * @param inputOffset the offset in input where the input starts
     * @param inputLen the input length
     * @param output the byte array for the result
     * @param outputOffset the offset in output where the result is stored
     * @return the number of bytes stored in output
     * @throws ShortBufferException if there is insufficient space in the output
     *         byte array
     */
    @Override
    public int update(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException {
        return cipher
                .update(input, inputOffset, inputLen, output, outputOffset);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation. The data is encrypted or decrypted, depending on
     * how this cipher was initialized.
     *
     * @param inBuffer the input ByteBuffer
     * @param outBuffer the output ByteBuffer
     * @return int number of bytes stored in <code>output</code>
     * @throws BadPaddingException if this cipher is in decryption mode, and
     *         (un)padding has been requested, but the decrypted data is not
     *         bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *         padding has been requested (only in encryption mode), and the
     *         total input length of the data processed by this cipher is not a
     *         multiple of block size; or if this encryption algorithm is unable
     *         to process the input data provided.
     * @throws ShortBufferException if the given output buffer is too small to
     *         hold the result
     */
    @Override
    public int doFinal(ByteBuffer inBuffer, ByteBuffer outBuffer)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
          return cipher.doFinal(inBuffer, outBuffer);
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     *
     * @param input the input byte array
     * @param inputOffset the offset in input where the input starts
     * @param inputLen the input length
     * @param output the byte array for the result
     * @param outputOffset the offset in output where the result is stored
     * @return the number of bytes stored in output
     * @throws ShortBufferException if the given output byte array is too small
     *         to hold the result
     * @throws BadPaddingException if this cipher is in decryption mode, and
     *         (un)padding has been requested, but the decrypted data is not
     *         bounded by the appropriate padding bytes
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *         padding has been requested (only in encryption mode), and the
     *         total input length of the data processed by this cipher is not a
     *         multiple of block size; or if this encryption algorithm is unable
     *         to process the input data provided.
     */
    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        return cipher.doFinal(input, inputOffset, inputLen, output,outputOffset);
    }

    /**
     * Continues a multi-part update of the Additional Authentication
     * Data (AAD).
     * <p>
     * Calls to this method provide AAD to the cipher when operating in
     * modes such as AEAD (GCM).  If this cipher is operating in
     * either GCM mode, all AAD must be supplied before beginning
     * operations on the ciphertext (via the {@code update} and
     * {@code doFinal} methods).
     *
     * @param aad the buffer containing the Additional Authentication Data
     *
     * @throws IllegalArgumentException if the {@code aad}
     * byte array is null
     * @throws IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized), does not accept AAD, or if
     * operating in either GCM mode and one of the {@code update}
     * methods has already been called for the active
     * encryption/decryption operation
     * @throws UnsupportedOperationException if the implementation {@code cipher}
     * doesn't support this operation.
     */
    @Override
    public void updateAAD(byte[] aad) throws IllegalArgumentException,
            IllegalStateException, UnsupportedOperationException {
        if (aad == null) {
            throw new IllegalArgumentException("aad buffer is null");
        }
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }
        if (aad.length == 0) {
            return;
        }

        cipher.updateAAD(aad);
    }

    /**
     * Continues a multi-part update of the Additional Authentication
     * Data (AAD).
     * <p>
     * Calls to this method provide AAD to the cipher when operating in
     * modes such as AEAD (GCM).  If this cipher is operating in
     * either GCM mode, all AAD must be supplied before beginning
     * operations on the ciphertext (via the {@code update} and
     * {@code doFinal} methods).
     *
     * @param aad the buffer containing the Additional Authentication Data
     *
     * @throws IllegalArgumentException if the {@code aad}
     * byte array is null
     * @throws IllegalStateException if this cipher is in a wrong state
     * (e.g., has not been initialized), does not accept AAD, or if
     * operating in either GCM mode and one of the {@code update}
     * methods has already been called for the active
     * encryption/decryption operation
     * @throws UnsupportedOperationException if the implementation {@code cipher}
     * doesn't support this operation.
     */
    @Override
    public void updateAAD(ByteBuffer aad) throws IllegalArgumentException,
            IllegalStateException, UnsupportedOperationException {
        if (aad == null) {
            throw new IllegalArgumentException("aad buffer is null");
        }
        if (!initialized) {
            throw new IllegalStateException("Cipher not initialized");
        }

        int aadLen = aad.limit() - aad.position();
        if (aadLen == 0) {
            return;
        }
        byte[] aadBytes = new byte[aadLen];
        aad.get(aadBytes);
        cipher.updateAAD(aadBytes);
    }

    /**
     * Closes the OpenSSL cipher. Clean the Openssl native context.
     */
    @Override
    public void close() {
        cipher.clean();
    }
}
