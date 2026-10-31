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

func awaitGenerateKeyPair(generator: AsyKeyGenerator): KeyPair {
    let monitor = Monitor()
    var result: ?KeyPair = None
    var errResult: ?BusinessException = None
    let callback: AsyncCallback<KeyPair> = { err, keyPair =>
        if (let Some(e) <- err) {
            errResult = e
        } else if (let Some(kp) <- keyPair) {
            result = kp
        }
        synchronized(monitor) {
            monitor.notify()
        }
    }
    generator.generateKeyPair(callback)
    synchronized(monitor) {
        monitor.wait(timeout: Duration.second * 10)
    }
    if (let Some(e) <- errResult) {
        throw e
    }
    return result ?? throw Exception("generateKeyPair timeout")
}

/**
 * 测试ohos.crypto_framework模块的PriKey、PubKey、KeyPair类操作功能
 */
@Test
class Test_Asy_Key_Operations_Add {
    /**
     * 测试KeyPair.pubKey属性 - 有效等价类：验证pubKey可访问且algName正确
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_keyPair_pubKey() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            @Expect(keyPair.pubKey.algName == "RSA4096")
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试KeyPair.priKey属性 - 有效等价类：验证priKey可访问且algName正确
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_keyPair_priKey() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            @Expect(keyPair.priKey.algName == "RSA4096")
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.format属性 - 有效等价类：验证format返回非空字符串
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_format() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            @Expect(keyPair.pubKey.format.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.algName属性 - 有效等价类：验证algName对于RSA4096正确
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_algName_RSA4096() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            @Expect(keyPair.pubKey.algName == "RSA4096")
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.format属性 - 有效等价类：验证format返回非空字符串
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_format() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            @Expect(keyPair.priKey.format.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.algName属性 - 有效等价类：验证algName对于RSA4096正确
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_algName_RSA4096() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            @Expect(keyPair.priKey.algName == "RSA4096")
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.getEncoded API - 有效等价类：获取RSA4096公钥编码数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getEncoded_RSA4096() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let encoded: DataBlob = keyPair.pubKey.getEncoded()
            @Expect(encoded.data.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.getEncoded API - 有效等价类：获取RSA4096私钥编码数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getEncoded_RSA4096() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let encoded: DataBlob = keyPair.priKey.getEncoded()
            @Expect(encoded.data.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.getEncodedDer API - 有效等价类：获取RSA4096公钥X509格式DER编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getEncodedDer_X509() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let encoded: DataBlob = keyPair.pubKey.getEncodedDer("X509")
            @Expect(encoded.data.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.getEncodedDer API - 有效等价类：获取RSA4096私钥PKCS8格式DER编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getEncodedDer_PKCS8() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let encoded: DataBlob = keyPair.priKey.getEncodedDer("PKCS8")
            @Expect(encoded.data.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.getEncodedDer API - 异常：无效格式名，错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getEncodedDer_invalidFormat() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
        let keyPair: KeyPair = awaitGenerateKeyPair(generator)
        try {
            keyPair.pubKey.getEncodedDer("INVALID_FORMAT")
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }

    /**
     * 测试PriKey.getEncodedDer API - 异常：无效格式名，错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getEncodedDer_invalidFormat() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
        let keyPair: KeyPair = awaitGenerateKeyPair(generator)
        try {
            keyPair.priKey.getEncodedDer("INVALID_FORMAT")
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }

    /**
     * 测试PubKey.getEncodedPem API - 有效等价类：获取RSA4096公钥X509格式PEM编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getEncodedPem_X509() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let pem: String = keyPair.pubKey.getEncodedPem("X509")
            @Expect(pem.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.getEncodedPem API - 有效等价类：获取RSA4096私钥PKCS8格式PEM编码
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getEncodedPem_PKCS8() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let pem: String = keyPair.priKey.getEncodedPem("PKCS8")
            @Expect(pem.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.getEncodedPem API - 异常：无效格式名，错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getEncodedPem_invalidFormat() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
        let keyPair: KeyPair = awaitGenerateKeyPair(generator)
        try {
            keyPair.pubKey.getEncodedPem("INVALID_FORMAT")
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }

    /**
     * 测试PriKey.getEncodedPem API - 异常：无效格式名，错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getEncodedPem_invalidFormat() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
        let keyPair: KeyPair = awaitGenerateKeyPair(generator)
        try {
            keyPair.priKey.getEncodedPem("INVALID_FORMAT")
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }

    /**
     * 测试PubKey.getAsyKeySpec API - 有效等价类：获取RSA公钥的模数n
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getAsyKeySpec_RsaNBn() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let spec: ResultSpec = keyPair.pubKey.getAsyKeySpec(AsyKeySpecItem.RsaNBn)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.getAsyKeySpec API - 有效等价类：获取RSA公钥的公钥指数e
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getAsyKeySpec_RsaPkBn() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let spec: ResultSpec = keyPair.pubKey.getAsyKeySpec(AsyKeySpecItem.RsaPkBn)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.getAsyKeySpec API - 有效等价类：获取RSA私钥的模数n
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getAsyKeySpec_RsaNBn() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let spec: ResultSpec = keyPair.priKey.getAsyKeySpec(AsyKeySpecItem.RsaNBn)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.getAsyKeySpec API - 有效等价类：获取RSA私钥的私钥指数d
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getAsyKeySpec_RsaSkBn() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let spec: ResultSpec = keyPair.priKey.getAsyKeySpec(AsyKeySpecItem.RsaSkBn)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.getAsyKeySpec API - 异常：获取ECC参数但密钥为RSA，错误码801
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getAsyKeySpec_mismatch() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
        let keyPair: KeyPair = awaitGenerateKeyPair(generator)
        try {
            keyPair.pubKey.getAsyKeySpec(AsyKeySpecItem.EccPkXBn)
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 801)
        }
    }

    /**
     * 测试PriKey.getAsyKeySpec API - 异常：获取ECC参数但密钥为RSA，错误码801
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getAsyKeySpec_mismatch() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
        let keyPair: KeyPair = awaitGenerateKeyPair(generator)
        try {
            keyPair.priKey.getAsyKeySpec(AsyKeySpecItem.EccSkBn)
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 801)
        }
    }

    /**
     * 测试PriKey.clearMem API - 有效等价类：清除私钥内存数据，无异常
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_clearMem() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            keyPair.priKey.clearMem()
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    // === ECC256 测试 ===

    /**
     * 测试PubKey.getEncoded API - 有效等价类：获取ECC256公钥编码数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getEncoded_ECC256() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("ECC256")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let encoded: DataBlob = keyPair.pubKey.getEncoded()
            @Expect(encoded.data.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.getEncoded API - 有效等价类：获取ECC256私钥编码数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getEncoded_ECC256() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("ECC256")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let encoded: DataBlob = keyPair.priKey.getEncoded()
            @Expect(encoded.data.size > 0)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.getAsyKeySpec API - 有效等价类：获取ECC私钥的椭圆曲线素数p
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getAsyKeySpec_EccFpPBn() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("ECC256")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let spec: ResultSpec = keyPair.priKey.getAsyKeySpec(AsyKeySpecItem.EccFpPBn)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PriKey.getAsyKeySpec API - 有效等价类：获取ECC私钥的私钥值sk
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_priKey_getAsyKeySpec_EccSkBn() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("ECC256")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let spec: ResultSpec = keyPair.priKey.getAsyKeySpec(AsyKeySpecItem.EccSkBn)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.getAsyKeySpec API - 有效等价类：获取ECC公钥的X坐标
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getAsyKeySpec_EccPkXBn() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("ECC256")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let spec: ResultSpec = keyPair.pubKey.getAsyKeySpec(AsyKeySpecItem.EccPkXBn)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试PubKey.getAsyKeySpec API - 有效等价类：获取ECC公钥的Y坐标
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_pubKey_getAsyKeySpec_EccPkYBn() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("ECC256")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let spec: ResultSpec = keyPair.pubKey.getAsyKeySpec(AsyKeySpecItem.EccPkYBn)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
}
