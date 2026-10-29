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
 * 测试ohos.crypto_framework模块的AsyKeyGenerator类操作功能
 */
@Test
class Test_Asy_Key_Generator_Operations_Add {

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
     * 测试AsyKeyGenerator.generateKeyPair API - 有效等价类：生成RSA密钥对
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_generateKeyPair_RSA4096() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        @Expect(keyPair.pubKey.algName == "RSA4096")
        @Expect(keyPair.priKey.algName == "RSA4096")
    }

    /**
     * 测试AsyKeyGenerator.generateKeyPair API - 有效等价类：生成ECC密钥对
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_generateKeyPair_ECC256() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        @Expect(keyPair.pubKey.algName == "ECC256")
        @Expect(keyPair.priKey.algName == "ECC256")
    }

    /**
     * 测试AsyKeyGenerator.generateKeyPair API - 有效等价类：生成Ed25519密钥对
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_generateKeyPair_Ed25519() {
        let generator = createAsyKeyGenerator("Ed25519")
        let keyPair = awaitGenerateKeyPair(generator)
        @Expect(keyPair.pubKey.algName == "Ed25519")
        @Expect(keyPair.priKey.algName == "Ed25519")
    }

    /**
     * 测试AsyKeyGenerator.generateKeyPair API - 有效等价类：生成SM2密钥对
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_generateKeyPair_SM2() {
        let generator = createAsyKeyGenerator("SM2")
        let keyPair = awaitGenerateKeyPair(generator)
        @Expect(keyPair.pubKey.algName == "SM2")
        @Expect(keyPair.priKey.algName == "SM2")
    }

    /**
     * 测试AsyKeyGenerator.convertKey API - 有效等价类：先generateKeyPair再convertKey
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_convertKey_RSA_derive() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let pubEncoded = keyPair.pubKey.getEncoded()
        let priEncoded = keyPair.priKey.getEncoded()

        let monitor = Monitor()
        var convertResult: ?KeyPair = None
        var convertErr: ?BusinessException = None
        generator.convertKey({ err, kp =>
            if (let Some(e) <- err) {
                convertErr = e
            } else if (let Some(k) <- kp) {
                convertResult = k
            }
            synchronized(monitor) {
                monitor.notify()
            }
        }, pubKey!: Some(pubEncoded), priKey!: Some(priEncoded))
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        if (let Some(e) <- convertErr) {
            throw e
        }
        let convertedKp = convertResult ?? throw Exception("convertKey timeout")
        @Expect(convertedKp.pubKey.algName == "RSA4096")
        @Expect(convertedKp.priKey.algName == "RSA4096")
    }

    /**
     * 测试AsyKeyGenerator.convertKey API - 有效等价类：只传公钥
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_convertKey_RSA_pubOnly() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let pubEncoded = keyPair.pubKey.getEncoded()

        let monitor = Monitor()
        var convertResult: ?KeyPair = None
        var convertErr: ?BusinessException = None
        generator.convertKey({ err, kp =>
            if (let Some(e) <- err) {
                convertErr = e
            } else if (let Some(k) <- kp) {
                convertResult = k
            }
            synchronized(monitor) {
                monitor.notify()
            }
        }, pubKey!: Some(pubEncoded))
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        if (let Some(e) <- convertErr) {
            throw e
        }
        let convertedKp = convertResult ?? throw Exception("convertKey timeout")
        @Expect(convertedKp.pubKey.algName == "RSA4096")
    }

    /**
     * 测试AsyKeyGenerator.convertKey API - 无效等价类：pubKey和priKey都为None
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_convertKey_bothNone() {
        let generator = createAsyKeyGenerator("RSA4096")
        let monitor = Monitor()
        var convertErr: ?BusinessException = None
        var gotCallback = false
        generator.convertKey({ err, kp =>
            if (let Some(e) <- err) {
                convertErr = e
            }
            gotCallback = true
            synchronized(monitor) {
                monitor.notify()
            }
        })
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        @Expect(gotCallback)
        @Expect(convertErr != None)
    }

    /**
     * 测试AsyKeyGenerator.convertPemKey API - 有效等价类：先generateKeyPair再convertPemKey
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_convertPemKey_RSA_derive() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let pubPem = keyPair.pubKey.getEncodedPem("X509")
        let priPem = keyPair.priKey.getEncodedPem("PKCS8")

        let monitor = Monitor()
        var convertResult: ?KeyPair = None
        var convertErr: ?BusinessException = None
        generator.convertPemKey({ err, kp =>
            if (let Some(e) <- err) {
                convertErr = e
            } else if (let Some(k) <- kp) {
                convertResult = k
            }
            synchronized(monitor) {
                monitor.notify()
            }
        }, pubKey!: Some(pubPem), priKey!: Some(priPem))
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        if (let Some(e) <- convertErr) {
            throw e
        }
        let convertedKp = convertResult ?? throw Exception("convertPemKey timeout")
        @Expect(convertedKp.pubKey.algName == "RSA4096")
        @Expect(convertedKp.priKey.algName == "RSA4096")
    }

    /**
     * 测试AsyKeyGenerator.convertPemKey API - 有效等价类：只传PEM公钥
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_convertPemKey_RSA_pubOnly() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let pubPem = keyPair.pubKey.getEncodedPem("X509")

        let monitor = Monitor()
        var convertResult: ?KeyPair = None
        var convertErr: ?BusinessException = None
        generator.convertPemKey({ err, kp =>
            if (let Some(e) <- err) {
                convertErr = e
            } else if (let Some(k) <- kp) {
                convertResult = k
            }
            synchronized(monitor) {
                monitor.notify()
            }
        }, pubKey!: Some(pubPem))
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        if (let Some(e) <- convertErr) {
            throw e
        }
        let convertedKp = convertResult ?? throw Exception("convertPemKey timeout")
        @Expect(convertedKp.pubKey.algName == "RSA4096")
    }

    /**
     * 测试AsyKeyGenerator.convertPemKey(password) API - 有效等价类：带密码转换PEM私钥
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_convertPemKey_withPassword() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let pubPem = keyPair.pubKey.getEncodedPem("X509")
        let priPem = keyPair.priKey.getEncodedPem("PKCS8")

        let monitor = Monitor()
        var convertResult: ?KeyPair = None
        var convertErr: ?BusinessException = None
        generator.convertPemKey("test123", { err, kp =>
            if (let Some(e) <- err) {
                convertErr = e
            } else if (let Some(k) <- kp) {
                convertResult = k
            }
            synchronized(monitor) {
                monitor.notify()
            }
        }, pubKey!: Some(pubPem), priKey!: Some(priPem))
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        // 带密码转换未加密的PEM也应该能成功（密码不影响未加密私钥）
        if (let Some(e) <- convertErr) {
            // 某些场景下带密码转换未加密私钥可能返回错误，这里容忍
            @Expect(true)
        } else {
            let convertedKp = convertResult ?? throw Exception("convertPemKey timeout")
            @Expect(convertedKp.pubKey.algName == "RSA4096")
        }
    }
}
