package org.apache.commons.crypto.stream;

import java.io.IOException;

/**
 * Created by xiandake on 10/21/16.
 */
public class GcmNoPaddingCipherStreamTest extends AbstractCipherStreamTest {

    @Override
    public void setUp() throws IOException {
        transformation = "AES/GCM/NoPadding";
    }
}
