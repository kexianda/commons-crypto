package org.apache.commons.crypto.cipher;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;

/**
 * For  CTR, CBC mode
 *
 */
class OpensslCommonMode extends OpensslBlockCipher{

    //private long context = 0;
    //private int mode = Openssl.DECRYPT_MODE;

    @Override
    public void init(int mode, int alg, int padding, byte[] key, AlgorithmParameterSpec params)
            throws InvalidAlgorithmParameterException {
        this.mode = mode;
        byte[] iv;
        if (params instanceof IvParameterSpec) {
            iv = ((IvParameterSpec) params).getIV();
        } else {
            // other AlgorithmParameterSpec is not supported now.
            throw new InvalidAlgorithmParameterException("Illegal parameters");
        }
        context = OpensslNative.init(context, mode, alg, padding, key, iv);
    }

    @Override
    public int update(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        int len = OpensslNative.update(context, input, input.position(),
                input.remaining(), output, output.position(),
                output.remaining());
        input.position(input.limit());
        output.position(output.position() + len);

        return len;
    }

    @Override
    public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException {
        return OpensslNative.updateByteArray(context, input, inputOffset,
                inputLen, output, outputOffset, output.length - outputOffset);
    }

    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {

        int len = OpensslNative.updateByteArray(context, input, inputOffset,
                    inputLen, output, outputOffset, output.length - outputOffset);

        len +=  OpensslNative.doFinalByteArray(context, output, outputOffset + len,
                output.length - outputOffset);

        return len;
    }

    @Override
    public int doFinal(ByteBuffer input, ByteBuffer output)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        int totalLen = 0;
        int len = OpensslNative.update(context, input, input.position(),
                input.remaining(), output, output.position(), output.remaining());
        totalLen += len;

        input.position(input.limit());
        output.position(output.position() + len);

        len = OpensslNative.doFinal(context, output, output.position(),
            output.remaining());
        totalLen += len;

        output.position(output.position() + len);

        return totalLen;
    }

    @Override
    public void updateAAD(byte[] aad) {
        throw new UnsupportedOperationException(
                "The underlying Cipher implementation "
                        +  "does not support this method");
    }
}
