package org.apache.commons.crypto.cipher;


import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * The Openssl EVP API slightly differ from JCE API.
 * OpensslGaloisCounterMode provide JCE -like behavior, using OpenSSL EVP API
 *
 * @since 1.1
 */
class OpensslGaloisCounterMode extends OpensslBlockCipher{

//    private long context = 0;
//    private int mode = Openssl.DECRYPT_MODE;

    // buffer for AAD data; if consumed, set as null
    private ByteArrayOutputStream aadBuffer = new ByteArrayOutputStream();
    private int tagBitLen = -1;

    static final int DEFAULT_TAG_LEN = 16;

    // buffer for storing input in decryption, not used for encryption
    private ByteArrayOutputStream inBuffer = null;

    @Override
    public void init(int mode, int alg, int padding, byte[] key, AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {

        this.mode = mode;
        byte[] iv;
        if(params instanceof GCMParameterSpec) {
            GCMParameterSpec gcmParam = (GCMParameterSpec) params;
            iv = gcmParam.getIV();
            this.tagBitLen = gcmParam.getTLen();
        } else {
            // other AlgorithmParameterSpec is not supported now.
            throw new InvalidAlgorithmParameterException("Illegal parameters");
        }

        if (this.mode == Openssl.DECRYPT_MODE) {
            inBuffer = new ByteArrayOutputStream();
        }

        context = OpensslNative.init(context, mode, alg, padding, key, iv);
    }

    @Override
    public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        processAAD();

        int len;
        if (this.mode == Openssl.DECRYPT_MODE) {
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

        if (this.mode == Openssl.DECRYPT_MODE) {
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
        if (this.mode == Openssl.DECRYPT_MODE) {
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
            Openssl.evpCipherCtxCtrl(context, EvpCtrlValues.AEAD_SET_TAG.getValue(), getTagLen(), tag);
        } else {
            len = OpensslNative.updateByteArray(context, input, inputOffset,
                    inputLen, output, outputOffset, output.length - outputOffset);
        }

        len +=  OpensslNative.doFinalByteArray(context, output, outputOffset + len,
                output.length - outputOffset);

        // Keep the similar behavior as JCE, append the tag to end of output
        if(this.mode == Openssl.ENCRYPT_MODE) {
            ByteBuffer tag;
            tag = ByteBuffer.allocate(getTagLen());
            Openssl.evpCipherCtxCtrl(context, EvpCtrlValues.AEAD_GET_TAG.getValue(), getTagLen(), tag);
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
        if (this.mode == Openssl.DECRYPT_MODE) {
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
            Openssl.evpCipherCtxCtrl(context, EvpCtrlValues.AEAD_SET_TAG.getValue(),
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
        if (this.mode == Openssl.ENCRYPT_MODE) {
            ByteBuffer tag;
            tag = ByteBuffer.allocate(getTagLen());
            Openssl.evpCipherCtxCtrl(context, EvpCtrlValues.AEAD_GET_TAG.getValue(), getTagLen(), tag);
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
}
