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

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.StringTokenizer;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.commons.crypto.utils.NativeCodeLoader;
import org.apache.commons.crypto.utils.Utils;

/**
 * OpenSSL cryptographic wrapper using JNI. Currently only AES-CTR is supported.
 * It's flexible to add other crypto algorithms/modes.
 */
public final class Openssl {
    private static final Log LOG = LogFactory.getLog(Openssl.class.getName());

    // Mode constant defined by Openssl JNI
    public static final int ENCRYPT_MODE = 1;
    public static final int DECRYPT_MODE = 0;

    static final int DEFAULT_TAG_LEN = 16;

    private int mode = Openssl.DECRYPT_MODE;

    // buffer for AAD data; if consumed, set as null
    private byte[] aadBuffer;
    private int tagBitLen = -1;

    // buffer for storing input in decryption, not used for encryption
    private ByteArrayOutputStream ibuffer = null;

    /** Currently only support AES/CTR/NoPadding. */
    private static enum AlgorithmMode {
        AES_CTR, AES_CBC, AES_GCM;

        static int get(String algorithm, String mode)
                throws NoSuchAlgorithmException {
            try {
                return AlgorithmMode.valueOf(algorithm + "_" + mode).ordinal();
            } catch (Exception e) {
                throw new NoSuchAlgorithmException(
                        "Doesn't support algorithm: " + algorithm
                                + " and mode: " + mode);
            }
        }
    }

    private static enum Padding {
        NoPadding, PKCS5Padding;

        static int get(String padding) throws NoSuchPaddingException {
            try {
                return Padding.valueOf(padding).ordinal();
            } catch (Exception e) {
                throw new NoSuchPaddingException("Doesn't support padding: "
                        + padding);
            }
        }
    }

    /**
     * This enum is defined for OpensslNative.ctrl() to allow various cipher
     * specific parameters to be determined and set.
     * see the macro definitions in openssl/evp.h
     */
    private enum CtrlValues {

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

        CtrlValues(int value) {
            this.value = value;
        }

        public int getValue() {
            return value;
        }

    }

    private long context = 0;
    private final int algorithm;
    private final int padding;

    private static final String loadingFailureReason;

    static {
        String loadingFailure = null;
        try {
            if (NativeCodeLoader.isNativeCodeLoaded()) {
                OpensslNative.initIDs();
            }
        } catch (Throwable t) {
            loadingFailure = t.getMessage();
            LOG.debug("Failed to load OpenSSL CryptoCipher.", t);
        } finally {
            loadingFailureReason = loadingFailure;
        }
    }

    /**
     * Gets the failure reason when loading Openssl native.
     *
     * @return the failure reason.
     */
    public static String getLoadingFailureReason() {
        return loadingFailureReason;
    }

    private Openssl(long context, int algorithm, int padding) {
        this.context = context;
        this.algorithm = algorithm;
        this.padding = padding;
    }

    /**
     * Return an <code>OpensslCipher</code> object that implements the specified
     * transformation.
     *
     * @param transformation the name of the transformation, e.g.,
     *        AES/CTR/NoPadding.
     * @return OpensslCipher an <code>OpensslCipher</code> object
     * @throws NoSuchAlgorithmException if <code>transformation</code> is null,
     *         empty, in an invalid format, or if Openssl doesn't implement the
     *         specified algorithm.
     * @throws NoSuchPaddingException if <code>transformation</code> contains a
     *         padding scheme that is not available.
     */
    public static final Openssl getInstance(String transformation)
            throws NoSuchAlgorithmException, NoSuchPaddingException {
        Transform transform = tokenizeTransformation(transformation);
        int algorithmMode = AlgorithmMode.get(transform.algorithm,
                transform.mode);
        int padding = Padding.get(transform.padding);
        long context = OpensslNative.initContext(algorithmMode, padding);
        return new Openssl(context, algorithmMode, padding);
    }

    /** Nested class for algorithm, mode and padding. */
    private static class Transform {
        final String algorithm;
        final String mode;
        final String padding;

        public Transform(String algorithm, String mode, String padding) {
            this.algorithm = algorithm;
            this.mode = mode;
            this.padding = padding;
        }
    }

    private static Transform tokenizeTransformation(String transformation)
            throws NoSuchAlgorithmException {
        if (transformation == null) {
            throw new NoSuchAlgorithmException("No transformation given.");
        }

        /*
         * Array containing the components of a Cipher transformation: index 0:
         * algorithm (e.g., AES) index 1: mode (e.g., CTR) index 2: padding
         * (e.g., NoPadding)
         */
        String[] parts = new String[3];
        int count = 0;
        StringTokenizer parser = new StringTokenizer(transformation, "/");
        while (parser.hasMoreTokens() && count < 3) {
            parts[count++] = parser.nextToken().trim();
        }
        if (count != 3 || parser.hasMoreTokens()) {
            throw new NoSuchAlgorithmException(
                    "Invalid transformation format: " + transformation);
        }
        return new Transform(parts[0], parts[1], parts[2]);
    }

    /**
     * Initialize this cipher with a key and IV.
     *
     * @param mode {@link #ENCRYPT_MODE} or {@link #DECRYPT_MODE}
     * @param key crypto key
     * @param params the algorithm parameters
     * @throws InvalidAlgorithmParameterException if IV length is wrong
     */
    public void init(int mode, byte[] key, AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {

        this.mode = mode;
        byte[] iv;
        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();
        } else if(params instanceof GCMParameterSpec) {
            GCMParameterSpec gcmParam = (GCMParameterSpec) params;
            iv = gcmParam.getIV();
            this.tagBitLen = gcmParam.getTLen();
        } else {
            // other AlgorithmParameterSpec is not supported now.
            throw new InvalidAlgorithmParameterException("Illegal parameters");
        }

        if (algorithm == AlgorithmMode.AES_GCM.ordinal()
                && this.mode == Openssl.DECRYPT_MODE) {
            ibuffer = new ByteArrayOutputStream();
        }

        context = OpensslNative
                .init(context, mode, algorithm, padding, key, iv);
    }

    /**
     * <p>
     * Continues a multiple-part encryption or decryption operation. The data is
     * encrypted or decrypted, depending on how this cipher was initialized.
     * </p>
     *
     * <p>
     * All <code>input.remaining()</code> bytes starting at
     * <code>input.position()</code> are processed. The result is stored in the
     * output buffer.
     * </p>
     *
     * <p>
     * Upon return, the input buffer's position will be equal to its limit; its
     * limit will not have changed. The output buffer's position will have
     * advanced by n, when n is the value returned by this method; the output
     * buffer's limit will not have changed.
     * </p>
     *
     * If <code>output.remaining()</code> bytes are insufficient to hold the
     * result, a <code>ShortBufferException</code> is thrown.
     *
     * @param input the input ByteBuffer
     * @param output the output ByteBuffer
     * @return int number of bytes stored in <code>output</code>
     * @throws ShortBufferException if there is insufficient space in the output
     *         buffer
     */
    public int update(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException {
        checkState();
        Utils.checkArgument(input.isDirect() && output.isDirect(),
                "Direct buffers are required.");

        processAAD();

        int len;
        if (algorithm == AlgorithmMode.AES_GCM.ordinal()
                && this.mode == Openssl.DECRYPT_MODE) {
            // store internally until doFinal(decrypt) is called because
            // spec mentioned that only return recovered data after tag
            // is successfully verified
            int inputLen = input.remaining();
            byte[] inputBuf = new byte[inputLen];
            input.get(inputBuf, 0, inputLen);
            ibuffer.write(inputBuf, 0, inputLen);
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
    public int update(byte[] input, int inputOffset, int inputLen,
            byte[] output, int outputOffset) throws ShortBufferException {
        checkState();
        processAAD();

        if (algorithm == AlgorithmMode.AES_GCM.ordinal()
                && this.mode == Openssl.DECRYPT_MODE) {
            // store internally until doFinal(decrypt) is called because
            // spec mentioned that only return recovered data after tag
            // is successfully verified
            ibuffer.write(input, inputOffset, inputLen);
            return 0;
        } else {
            return OpensslNative.updateByteArray(context, input, inputOffset,
                    inputLen, output, outputOffset, output.length - outputOffset);
        }
    }

    /**
     * <p>
     * Finishes a multiple-part operation. The data is encrypted or decrypted,
     * depending on how this cipher was initialized.
     * </p>
     *
     * <p>
     * The result is stored in the output buffer. Upon return, the output
     * buffer's position will have advanced by n, where n is the value returned
     * by this method; the output buffer's limit will not have changed.
     * </p>
     *
     * <p>
     * If <code>output.remaining()</code> bytes are insufficient to hold the
     * result, a <code>ShortBufferException</code> is thrown.
     * </p>
     *
     * <p>
     * Upon finishing, this method resets this cipher object to the state it was
     * in when previously initialized. That is, the object is available to
     * encrypt or decrypt more data.
     * </p>
     *
     * If any exception is thrown, this cipher object need to be reset before it
     * can be used again.
     *
     * @param output the output ByteBuffer
     * @return int number of bytes stored in <code>output</code>
     * @throws ShortBufferException if the given output byte array is too small
     *         to hold the result.
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *         padding has been requested (only in encryption mode), and the
     *         total input length of the data processed by this cipher is not a
     *         multiple of block size; or if this encryption algorithm is unable
     *         to process the input data provided.
     * @throws BadPaddingException if this cipher is in decryption mode, and
     *         (un)padding has been requested, but the decrypted data is not
     *         bounded by the appropriate padding bytes
     */
    public int doFinal(ByteBuffer output) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        checkState();
        Utils.checkArgument(output.isDirect(), "Direct buffer is required.");
        int len = OpensslNative.doFinal(context, output, output.position(),
                output.remaining());
        output.position(output.position() + len);
        return len;
    }

    /**
     * Encrypts or decrypts data in a single-part operation, or finishes a
     * multiple-part operation.
     *
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
    public int doFinal(byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        checkState();
        return OpensslNative.doFinalByteArray(context, output, outputOffset,
                output.length - outputOffset);
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
    public int doFinal(byte[] input, int inputOffset, int inputLen,
                       byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException{

        checkState();
        processAAD();

        int len = 0;
        if (algorithm == AlgorithmMode.AES_GCM.ordinal()
                && this.mode == Openssl.DECRYPT_MODE) {
            // if GCM-DECRYPT, we have to handle the buffered input
            // and the retrieve the trailing tag from input
            int inputOffsetFinal = inputOffset;
            int inputLenFinal = inputLen;
            byte[] inputFinal;
            if (ibuffer != null && ibuffer.size() > 0) {
                ibuffer.write(input, inputOffset, inputLen);
                inputFinal = ibuffer.toByteArray();
                inputOffsetFinal = 0;
                inputLenFinal = inputFinal.length;
                ibuffer.reset();
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
            ByteBuffer bfTag = ByteBuffer.allocateDirect(getTagLen());
            bfTag.put(input, input.length - getTagLen(), getTagLen());
            bfTag.flip();
            OpensslNative.ctrl(context, CtrlValues.AEAD_SET_TAG.getValue(), getTagLen(), bfTag);
        } else {
            len = OpensslNative.updateByteArray(context, input, inputOffset,
                    inputLen, output, outputOffset, output.length - outputOffset);
        }

        len +=  OpensslNative.doFinalByteArray(context, output, outputOffset + len,
                output.length - outputOffset);

        // Keep the similar behavior as JCE, append the tag to end of output
        if(algorithm == AlgorithmMode.AES_GCM.ordinal()
                && this.mode == Openssl.ENCRYPT_MODE) {
            ByteBuffer tag;
            tag = ByteBuffer.allocateDirect(getTagLen());
            OpensslNative.ctrl(context, CtrlValues.AEAD_GET_TAG.getValue(), getTagLen(), tag);
            tag.get(output, output.length-getTagLen(), getTagLen());
            len += getTagLen();
        }

        return len;
    }

    /**
     * <p>
     * Finishes a multiple-part operation. The data is encrypted or decrypted,
     * depending on how this cipher was initialized.
     * </p>
     *
     * <p>
     * The result is stored in the output buffer. Upon return, the output
     * buffer's position will have advanced by n, where n is the value returned
     * by this method; the output buffer's limit will not have changed.
     * </p>
     *
     * <p>
     * If <code>output.remaining()</code> bytes are insufficient to hold the
     * result, a <code>ShortBufferException</code> is thrown.
     * </p>
     *
     * <p>
     * Upon finishing, this method resets this cipher object to the state it was
     * in when previously initialized. That is, the object is available to
     * encrypt or decrypt more data.
     * </p>
     *
     * If any exception is thrown, this cipher object need to be reset before it
     * can be used again.
     *
     * @param input the input ByteBuffer
     * @param output the output ByteBuffer
     * @return int number of bytes stored in <code>output</code>
     * @throws ShortBufferException if the given output byte array is too small
     *         to hold the result.
     * @throws IllegalBlockSizeException if this cipher is a block cipher, no
     *         padding has been requested (only in encryption mode), and the
     *         total input length of the data processed by this cipher is not a
     *         multiple of block size; or if this encryption algorithm is unable
     *         to process the input data provided.
     * @throws BadPaddingException if this cipher is in decryption mode, and
     *         (un)padding has been requested, but the decrypted data is not
     *         bounded by the appropriate padding bytes
     */
    public int doFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException,
            IllegalBlockSizeException, BadPaddingException {
        checkState();
        Utils.checkArgument(output.isDirect(), "Direct buffer is required.");
        processAAD();

        int totalLen = 0;
        int len = 0;
        if (algorithm == AlgorithmMode.AES_GCM.ordinal()
                && this.mode == Openssl.DECRYPT_MODE) {
            // if GCM-DECRYPT, we have to handle the buffered input
            // and the retrieve the trailing tag from input
            if (ibuffer != null && ibuffer.size() > 0) {
                byte[] inputBytes = new byte[input.remaining()];
                input.get(inputBytes, 0, inputBytes.length);
                ibuffer.write(inputBytes, 0, inputBytes.length);
                byte[] inputFinal = ibuffer.toByteArray();
                ibuffer.reset();

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
            ByteBuffer bfTag = ByteBuffer.allocateDirect(getTagLen());
            bfTag.put(input);
            bfTag.flip();
            OpensslNative.ctrl(context, CtrlValues.AEAD_SET_TAG.getValue(),
                    getTagLen(), bfTag);
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
        if(algorithm == AlgorithmMode.AES_GCM.ordinal()
                && this.mode == Openssl.ENCRYPT_MODE) {
            ByteBuffer tag;
            tag = ByteBuffer.allocateDirect(getTagLen());
            OpensslNative.ctrl(context, CtrlValues.AEAD_GET_TAG.getValue(),
                    getTagLen(), tag);

            output.put(tag);
            totalLen += getTagLen();
        }

        return totalLen;
    }

    /** Forcibly clean the context. */
    public void clean() {
        if (context != 0) {
            OpensslNative.clean(context);
            context = 0;
        }
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
     */
    public void updateAAD(byte[] aad) {
        // must be called after initialized.
        aadBuffer = aad.clone();
    }

    /** Checks whether context is initialized. */
    private void checkState() {
        Utils.checkState(context != 0);
    }

    private void processAAD() {
        if (algorithm == AlgorithmMode.AES_GCM.ordinal()
                && aadBuffer != null
                && aadBuffer.length > 0) {
            OpensslNative.updateByteArray(context, aadBuffer, 0, aadBuffer.length, null, 0, 0);
            aadBuffer = null;
        }
    }

    private int getTagLen() {
        return tagBitLen < 0 ? DEFAULT_TAG_LEN : (tagBitLen >> 3);
    }

    @Override
    protected void finalize() throws Throwable {
        clean();
    }

}
