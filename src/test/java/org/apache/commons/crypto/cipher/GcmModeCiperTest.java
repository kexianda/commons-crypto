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
import java.security.Key;
import java.util.Properties;
import java.util.Random;

import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.utils.Utils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class GcmModeCiperTest {

    Properties props = null;
    String cipherClass = null;
    CipherTransformation transformation = CipherTransformation.AES_GCM_NOPADDING;

    @Before
    public void setup() {
        //init
        cipherClass = OpensslCipher.class.getName();

        props = new Properties();
        props.setProperty(ConfigurationKeys.COMMONS_CRYPTO_CIPHER_CLASSES_KEY,
                cipherClass);
    }

    /**
     * NIST AES Test Vectors
     * http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
     */
    @Test
    public void testGcmNistCase2() {
        // key length:          16 bytes
        // plain text length:   16 bytes
        // iv length:           12 bytes
        // aad length:          0 bytes

        String kHex = "00000000000000000000000000000000";
        String pHex = "00000000000000000000000000000000";
        String ivHex = "000000000000000000000000";
        String aadHex = "";

        String cHex = "0388dace60b6a392f328c2b971b2fe78";
        String tHex = "ab6e47d42cec13bdf53a67b21257bddf";

        testGcmEncryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmEncryptionByteBuffer(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmDecryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmReturnDataAfterTagVerified(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmArbitraryLengthUpdate(kHex, pHex, ivHex, aadHex, cHex, tHex);
    }

    @Test
    public void testGcmNistCase4() {
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           12 bytes
        // aad length:          20 bytes

        String kHex = "feffe9928665731c6d6a8f9467308308";
        String pHex = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";
        String ivHex = "cafebabefacedbaddecaf888";
        String aadHex = "feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";

        String cHex = "42831ec2217774244b7221b784d0d49c"
                + "e3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa05"
                + "1ba30b396a0aac973d58e091";
        String tHex = "5bc94fbc3221a5db94fae95ae7121a47";

        testGcmEncryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmEncryptionByteBuffer(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmDecryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmReturnDataAfterTagVerified(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmArbitraryLengthUpdate(kHex, pHex, ivHex, aadHex, cHex, tHex);
    }

    @Test
    public void testGcmNistCase5(){
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           8 bytes
        // aad length:          20 bytes

        String kHex = "feffe9928665731c6d6a8f9467308308";

        String pHex = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";

        String ivHex ="cafebabefacedbad"; // 64bits < 96bits

        String aadHex="feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";

        String cHex = "61353b4c2806934a777ff51fa22a4755"
                + "699b2a714fcdc6f83766e5f97b6c7423"
                + "73806900e49f24b22b097544d4896b42"
                + "4989b5e1ebac0f07c23f4598";

        String tHex = "3612d2e79e3b0785561be14aaca2fccb";

        testGcmEncryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmEncryptionByteBuffer(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmDecryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmReturnDataAfterTagVerified(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmArbitraryLengthUpdate(kHex, pHex, ivHex, aadHex, cHex, tHex);
    }

    @Test
    public void testGcmNistCase6(){
        // key length:          16 bytes
        // plain text length:   60 bytes
        // iv length:           60 bytes
        // aad length:          20 bytes

        String kHex = "feffe9928665731c6d6a8f9467308308";

        String pHex = "d9313225f88406e5a55909c5aff5269a"
                + "86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525"
                + "b16aedf5aa0de657ba637b39";

        String ivHex ="9313225df88406e555909c5aff5269aa"
                + "6a7a9538534f7da1e4c303d2a318a728"
                + "c3c0c95156809539fcf0e2429a6b5254"
                + "16aedbf5a0de6a57a637b39b"; // > 96bits

        String aadHex="feedfacedeadbeeffeedfacedeadbeef"
                + "abaddad2";

        String cHex = "8ce24998625615b603a033aca13fb894"
                + "be9112a5c3a211a8ba262a3cca7e2ca7"
                + "01e4a9a4fba43c90ccdcb281d48c7c6f"
                + "d62875d2aca417034c34aee5";

        String tHex = "619cc5aefffe0bfa462af43c1699d050";

        testGcmEncryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmEncryptionByteBuffer(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmDecryption(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmReturnDataAfterTagVerified(kHex, pHex, ivHex, aadHex, cHex, tHex);
        testGcmArbitraryLengthUpdate(kHex, pHex, ivHex, aadHex, cHex, tHex);
    }

    @Test(expected = AEADBadTagException.class)
    public void testGcmTamperedData() throws Exception {

        Random r = new Random();
        int textLength = r.nextInt(1024*1024);
        int ivLength = r.nextInt(60);
        int keyLength = 16;
        int tagLength = 128;  // bits
        int aadLength = r.nextInt(128);

        byte[] keyBytes = new byte[keyLength];
        byte[] plainBytes = new byte[textLength];
        byte[] ivBytes = new byte[ivLength];
        byte[] aadBytes = new byte[aadLength];

        r.nextBytes(keyBytes);
        r.nextBytes(plainBytes);
        r.nextBytes(ivBytes);
        r.nextBytes(aadBytes);

        byte[] encOutput = new byte[plainBytes.length + (tagLength >> 3)];
        byte[] decOutput = new byte[plainBytes.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(tagLength, ivBytes);
            c.init(CryptoCipher.ENCRYPT_MODE, key, iv);
            c.updateAAD(aadBytes);
            c.doFinal(plainBytes, 0, plainBytes.length, encOutput, 0);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }

        // Tamper the encrypted data.
        encOutput[0] = (byte)(encOutput[0] + 1);

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(tagLength, ivBytes);
            c.init(CryptoCipher.DECRYPT_MODE, key, iv);
            c.updateAAD(aadBytes);
            c.doFinal(encOutput, 0, encOutput.length, decOutput, 0);
            c.close();
        }
        catch (AEADBadTagException ex) {
            Assert.assertTrue("Tag mismatch!".equals(ex.getMessage()));
            throw ex;
        }
    }


    private void testGcmEncryption(String kHex, String pHex, String ivHex, String aadHex,
                              String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] input = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);
        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] expectedOutput = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] output = new byte[expectedOutput.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);

            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(CryptoCipher.ENCRYPT_MODE, key, iv);
            c.updateAAD(aad);

            c.doFinal(input, 0, input.length, output, 0);

            Assert.assertArrayEquals(expectedOutput, output);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmArbitraryLengthUpdate(String kHex, String pHex, String ivHex, String aadHex,
                                   String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] input = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);
        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] expectedOutput = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] encOutput = new byte[expectedOutput.length];
        byte[] decOutput = new byte[input.length];

        try {
            CryptoCipher enc = Utils.getCipherInstance(transformation, props);

            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            enc.init(CryptoCipher.ENCRYPT_MODE, key, iv);
            enc.updateAAD(aad);

            Random r = new Random();
            int partLen = r.nextInt(input.length);
            int len = enc.update(input, 0, partLen, encOutput, 0);
            Assert.assertTrue(len == partLen);
            len = enc.doFinal(input, partLen, input.length - partLen, encOutput, partLen);
            Assert.assertTrue(len == (input.length + (iv.getTLen() >> 3) - partLen));

            Assert.assertArrayEquals(expectedOutput, encOutput);
            enc.close();

            // Decryption
            CryptoCipher dec = Utils.getCipherInstance(transformation, props);
            dec.init(CryptoCipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(128, ivBytes));
            dec.updateAAD(aad);
            byte[] decInput = encOutput;
            partLen = r.nextInt(input.length);
            len = dec.update(decInput, 0, partLen, decOutput, 0);
            Assert.assertTrue(len == 0);
            len = dec.doFinal(decInput, partLen, decInput.length - partLen, decOutput, 0);
            Assert.assertTrue(len == input.length);

            Assert.assertArrayEquals(input, decOutput);
            dec.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmDecryption(String kHex, String pHex, String ivHex, String aadHex,
                                   String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] plainBytes = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);

        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] cipherBytes = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] input = cipherBytes;
        byte[] output = new byte[plainBytes.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);

            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(CryptoCipher.DECRYPT_MODE, key, iv);
            c.updateAAD(aad);
            c.doFinal(input, 0, input.length, output, 0);

            Assert.assertArrayEquals(plainBytes, output);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmReturnDataAfterTagVerified(String kHex, String pHex, String ivHex, String aadHex,
                                   String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] plainBytes = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);

        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] cipherBytes = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] input = cipherBytes;
        byte[] output = new byte[plainBytes.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);

            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(CryptoCipher.DECRYPT_MODE, key, iv);
            c.updateAAD(aad);

            //only return recovered data after tag is successfully verified
            int len = c.update(input, 0, input.length, output, 0);
            Assert.assertTrue(len == 0);
            len += c.doFinal(input, input.length, 0, output, 0);
            Assert.assertTrue(len == plainBytes.length);

            Assert.assertArrayEquals(plainBytes, output);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    private void testGcmEncryptionByteBuffer(String kHex, String pHex, String ivHex, String aadHex,
                                   String cHex, String tHex){

        byte[] keyBytes = DatatypeConverter.parseHexBinary(kHex);
        byte[] input = DatatypeConverter.parseHexBinary(pHex);
        byte[] ivBytes = DatatypeConverter.parseHexBinary(ivHex);
        byte[] aad = DatatypeConverter.parseHexBinary(aadHex);
        byte[] expectedOutput = DatatypeConverter.parseHexBinary(cHex+tHex);

        byte[] output = new byte[expectedOutput.length];

        try {
            CryptoCipher c = Utils.getCipherInstance(transformation, props);

            Key key = new SecretKeySpec(keyBytes, "AES");

            GCMParameterSpec iv = new GCMParameterSpec(128, ivBytes);
            c.init(CryptoCipher.ENCRYPT_MODE, key, iv);

            ByteBuffer bfAAD = ByteBuffer.allocateDirect(aad.length);
            bfAAD.put(aad);
            bfAAD.flip();
            c.updateAAD(bfAAD);

            ByteBuffer bfInput;
            ByteBuffer bfOutput;
            bfInput = ByteBuffer.allocateDirect(input.length);
            bfOutput = ByteBuffer.allocateDirect(output.length);
            bfInput.put(input);
            bfInput.flip();
            bfOutput.position(0);

            c.doFinal(bfInput, bfOutput);

            bfOutput.flip();
            bfOutput.get(output);
            Assert.assertArrayEquals(expectedOutput, output);
            c.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
