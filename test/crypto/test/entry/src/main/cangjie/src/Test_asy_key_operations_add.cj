/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ohos_app_cangjie_entry

import kit.CryptoArchitectureKit.*
import ohos.base.*
import std.math.numeric.*
import std.runtime.*
import std.sync.*
import std.time.*
import std.unittest.*
import std.unittest.common.*
import std.unittest.testmacro.*
import ohos.business_exception.*

/**
 * 测试ohos.crypto_framework模块的PriKey、PubKey、KeyPair类操作功能
 */
@Test
class Test_Asy_Key_Operations_Add {

    /**
     * 辅助函数：异步等待generateKeyPair回调结果
     */
    func awaitGenerateKeyPair(generator: AsyKeyGenerator): KeyPair {
        let monitor = Monitor()
        var result: ?KeyPair = None
        var errResult: ?BusinessException = None
        generator.generateKeyPair({ err, keyPair =>
            if (let Some(e) <- err) {
                errResult = e
            } else if (let Some(kp) <- keyPair) {
                result = kp
            }
            synchronized(monitor) {
                monitor.notify()
            }
        })
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        if (let Some(e) <- errResult) {
            throw e
        }
        return result ?? throw Exception("generateKeyPair timeout")
    }

    /**
     * 测试KeyPair.pubKey和KeyPair.priKey - 有效等价类：获取RSA密钥对的公钥和私钥
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_KeyPair_pubKey_priKey_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let pubKey: PubKey = keyPair.pubKey
        let priKey: PriKey = keyPair.priKey
        @Expect(pubKey.algName == "RSA4096")
        @Expect(priKey.algName == "RSA4096")
    }

    /**
     * 测试KeyPair.pubKey和KeyPair.priKey - 有效等价类：获取ECC密钥对的公钥和私钥
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_KeyPair_pubKey_priKey_ECC() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        @Expect(keyPair.pubKey.algName == "ECC256")
        @Expect(keyPair.priKey.algName == "ECC256")
    }

    /**
     * 测试PubKey.format - 有效等价类：获取RSA公钥格式
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_format_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let format = keyPair.pubKey.format
        @Expect(format.size > 0)
    }

    /**
     * 测试PriKey.format - 有效等价类：获取RSA私钥格式
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PriKey_format_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let format = keyPair.priKey.format
        @Expect(format.size > 0)
    }

    /**
     * 测试PubKey.algName - 有效等价类：获取公钥算法名
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_algName() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        @Expect(keyPair.pubKey.algName == "RSA4096")
    }

    /**
     * 测试PriKey.algName - 有效等价类：获取私钥算法名
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PriKey_algName() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        @Expect(keyPair.priKey.algName == "RSA4096")
    }

    /**
     * 测试PubKey.getEncoded - 有效等价类：获取RSA公钥DER编码数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_getEncoded_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let encoded = keyPair.pubKey.getEncoded()
        @Expect(encoded.data.size > 0)
    }

    /**
     * 测试PriKey.getEncoded - 有效等价类：获取RSA私钥DER编码数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PriKey_getEncoded_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let encoded = keyPair.priKey.getEncoded()
        @Expect(encoded.data.size > 0)
    }

    /**
     * 测试PubKey.getEncodedDer - 有效等价类：获取RSA公钥指定格式DER编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_getEncodedDer_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let encoded = keyPair.pubKey.getEncodedDer("X509")
        @Expect(encoded.data.size > 0)
    }

    /**
     * 测试PriKey.getEncodedDer - 有效等价类：获取RSA私钥指定格式DER编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PriKey_getEncodedDer_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let encoded = keyPair.priKey.getEncodedDer("PKCS8")
        @Expect(encoded.data.size > 0)
    }

    /**
     * 测试PubKey.getEncodedPem - 有效等价类：获取RSA公钥PEM编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_getEncodedPem_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let pem = keyPair.pubKey.getEncodedPem("X509")
        @Expect(pem.size > 0)
    }

    /**
     * 测试PriKey.getEncodedPem - 有效等价类：获取RSA私钥PEM编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PriKey_getEncodedPem_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let pem = keyPair.priKey.getEncodedPem("PKCS8")
        @Expect(pem.size > 0)
    }

    /**
     * 测试PubKey.getEncoded和PriKey.getEncoded - 有效等价类：ECC密钥对编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_AsyKey_getEncoded_ECC() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        @Expect(keyPair.pubKey.getEncoded().data.size > 0)
        @Expect(keyPair.priKey.getEncoded().data.size > 0)
    }

    /**
     * 测试PubKey.getEncodedDer - 有效等价类：ECC公钥压缩格式
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_getEncodedDer_ECC_compressed() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        let encoded = keyPair.pubKey.getEncodedDer("X509|COMPRESSED")
        @Expect(encoded.data.size > 0)
    }

    /**
     * 测试PubKey.getEncodedDer - 有效等价类：ECC公钥非压缩格式
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_getEncodedDer_ECC_uncompressed() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        let encoded = keyPair.pubKey.getEncodedDer("X509|UNCOMPRESSED")
        @Expect(encoded.data.size > 0)
    }

    /**
     * 测试PriKey.clearMem - 有效等价类：清除RSA私钥内存
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PriKey_clearMem_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        keyPair.priKey.clearMem()
        @Expect(true)
    }

    /**
     * 测试PriKey.getAsyKeySpec - 有效等价类：获取RSA私钥的n参数
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PriKey_getAsyKeySpec_RSA_n() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let spec = keyPair.priKey.getAsyKeySpec(AsyKeySpecItem.RsaNBigInt)
        @Expect(true)
    }

    /**
     * 测试PubKey.getAsyKeySpec - 有效等价类：获取RSA公钥的n参数
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_getAsyKeySpec_RSA_n() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let spec = keyPair.pubKey.getAsyKeySpec(AsyKeySpecItem.RsaNBigInt)
        @Expect(true)
    }

    /**
     * 测试PriKey.getAsyKeySpec - 有效等价类：获取ECC私钥的私钥值
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PriKey_getAsyKeySpec_ECC_d() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        let spec = keyPair.priKey.getAsyKeySpec(AsyKeySpecItem.EccDBigInt)
        @Expect(true)
    }

    /**
     * 测试PubKey.getAsyKeySpec - 有效等价类：获取ECC公钥的x坐标
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_getAsyKeySpec_ECC_x() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        let spec = keyPair.pubKey.getAsyKeySpec(AsyKeySpecItem.EccXBigInt)
        @Expect(true)
    }

    /**
     * 测试PubKey.getAsyKeySpec - 有效等价类：获取ECC公钥的y坐标
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_PubKey_getAsyKeySpec_ECC_y() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        let spec = keyPair.pubKey.getAsyKeySpec(AsyKeySpecItem.EccYBigInt)
        @Expect(true)
    }
}
