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
package org.apache.commons.crypto.stream;


import org.apache.commons.crypto.cipher.CipherTransformation;
import org.apache.commons.crypto.cipher.CryptoCipher;
import org.apache.commons.crypto.cipher.OpensslCipher;
import org.apache.commons.crypto.conf.ConfigurationKeys;
import org.apache.commons.crypto.utils.Utils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.util.Arrays;
import java.util.Properties;
import java.util.Random;

public class GCMCryptoStreamTest {
    Properties props = null;
    String cipherClass = null;
    CipherTransformation transformation = null;

    @Before
    public void setup() {
        transformation = CipherTransformation.AES_GCM_NOPADDING;
        cipherClass = OpensslCipher.class.getName();
        props = new Properties();
        props.setProperty(ConfigurationKeys.COMMONS_CRYPTO_CIPHER_CLASSES_KEY,
                cipherClass);
    }

    @Test
    public void testGCMStreamSanity(){
        Random r = new Random();
        int textLength = r.nextInt(1024*1024);
        int ivLength = 12;
        int keyLength = 16;
        int tagLength = 128;  // bits
        int aadLength = r.nextInt(128);

        int bufferLength = 512 + r.nextInt(textLength/2);

        byte[] keyBytes = new byte[keyLength];
        byte[] plainBytes = new byte[textLength];
        byte[] ivBytes = new byte[ivLength];
        byte[] aadBytes = new byte[aadLength];

        r.nextBytes(keyBytes);
        r.nextBytes(plainBytes);
        r.nextBytes(ivBytes);
        r.nextBytes(aadBytes);

        byte[] cipherBytes = new byte[plainBytes.length + (tagLength >> 3)];

        try {
            CryptoCipher enc = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec iv = new GCMParameterSpec(tagLength, ivBytes);
            enc.init(CryptoCipher.ENCRYPT_MODE, key, iv);
            enc.updateAAD(aadBytes);
            enc.doFinal(plainBytes, 0, plainBytes.length, cipherBytes, 0);
            enc.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }

        try {
            CryptoCipher dec = Utils.getCipherInstance(transformation, props);
            dec.init(CryptoCipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
                    new GCMParameterSpec(tagLength, ivBytes));
            dec.updateAAD(aadBytes);

            ByteArrayInputStream baio = new ByteArrayInputStream(cipherBytes);
            CryptoInputStream inStream = new CryptoInputStream(baio, dec, bufferLength);

            byte[] recoveredText = new byte[plainBytes.length];
            int length1 = r.nextInt(plainBytes.length);
            inStream.read(recoveredText, 0, length1);
            inStream.read(recoveredText, length1, plainBytes.length-length1);

            Assert.assertArrayEquals(plainBytes, recoveredText);

            inStream.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }

        try {
            CryptoCipher enc = Utils.getCipherInstance(transformation, props);
            Key key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec iv = new GCMParameterSpec(tagLength, ivBytes);
            enc.init(CryptoCipher.ENCRYPT_MODE, key, iv);
            enc.updateAAD(aadBytes);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            CryptoOutputStream outStream = new CryptoOutputStream(baos, enc, bufferLength);

            int length1 = r.nextInt(plainBytes.length);
            outStream.write(plainBytes, 0, length1);
            outStream.write(plainBytes, length1, plainBytes.length - length1);
            outStream.flush();

            byte[] cipherTextWithoutTag = baos.toByteArray();

            //get cipher bytes
            byte[] expectedCipherTextWithoutTag = Arrays.copyOfRange(cipherBytes, 0, plainBytes.length);
            Assert.assertArrayEquals(expectedCipherTextWithoutTag, cipherTextWithoutTag);

            outStream.close();
        }
        catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
