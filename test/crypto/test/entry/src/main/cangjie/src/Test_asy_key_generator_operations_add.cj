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
    let result = Box(None<KeyPair>)
    let errResult = Box(None<BusinessException>)
    let callback: AsyncCallback<KeyPair> = { err, keyPair =>
        if (let Some(e) <- err) {
            errResult.value = e
        } else if (let Some(kp) <- keyPair) {
            result.value = kp
        }
        synchronized(monitor) {
            monitor.notify()
        }
    }
    generator.generateKeyPair(callback)
    synchronized(monitor) {
        monitor.wait(timeout: Duration.second * 10)
    }
    if (let Some(e) <- errResult.value) {
        throw e
    }
    return result.value.getOrThrow(() => Exception("generateKeyPair timeout"))
}

/**
 * 测试ohos.crypto_framework模块的AsyKeyGenerator类操作功能
 */
@Test
class Test_Asy_Key_Generator_Operations_Add {
    /**
     * 测试AsyKeyGenerator.algName属性 - 有效等价类：返回正确的算法名称
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_asyKeyGenerator_algName() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA2048")
            @Expect(generator.algName == "RSA2048")
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试AsyKeyGenerator.generateKeyPair API - 有效等价类：生成RSA2048密钥对
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_asyKeyGenerator_generateKeyPair_RSA2048() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA2048")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            @Expect(keyPair.pubKey.algName == "RSA2048")
            @Expect(keyPair.priKey.algName == "RSA2048")
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试AsyKeyGenerator.convertKey API - 有效等价类：转换RSA2048密钥数据为密钥对
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_asyKeyGenerator_convertKey_RSA2048() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA2048")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let pubEncoded: DataBlob = keyPair.pubKey.getEncoded()
            let priEncoded: DataBlob = keyPair.priKey.getEncoded()

            let monitor = Monitor()
            let result = Box(None<KeyPair>)
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<KeyPair> = { err, kp =>
                if (let Some(e) <- err) {
                    errResult.value = e
                } else if (let Some(k) <- kp) {
                    result.value = k
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            generator.convertKey(callback, pubKey: Some(pubEncoded), priKey: Some(priEncoded))
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(result.value.isSome())
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试AsyKeyGenerator.convertKey API - 异常：pubKey和priKey都为None，回调错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_asyKeyGenerator_convertKey_bothNone() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA2048")

        try {
            let monitor = Monitor()
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<KeyPair> = { err, _ =>
                if (let Some(e) <- err) {
                    errResult.value = e
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            generator.convertKey(callback, pubKey: Option<DataBlob>.None, priKey: Option<DataBlob>.None)
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }

    /**
     * 测试AsyKeyGenerator.convertPemKey API（无密码） - 有效等价类：转换RSA2048 PEM格式密钥
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_asyKeyGenerator_convertPemKey_noPassword() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA2048")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let pubPem: String = keyPair.pubKey.getEncodedPem("X509")
            let priPem: String = keyPair.priKey.getEncodedPem("PKCS8")

            let monitor = Monitor()
            let result = Box(None<KeyPair>)
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<KeyPair> = { err, kp =>
                if (let Some(e) <- err) {
                    errResult.value = e
                } else if (let Some(k) <- kp) {
                    result.value = k
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            generator.convertPemKey(callback, pubKey: Some(pubPem), priKey: Some(priPem))
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(result.value.isSome())
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试AsyKeyGenerator.convertPemKey API（无密码） - 异常：无效PEM数据，回调错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_asyKeyGenerator_convertPemKey_invalidPem() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA2048")

        try {
            let monitor = Monitor()
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<KeyPair> = { err, _ =>
                if (let Some(e) <- err) {
                    errResult.value = e
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            generator.convertPemKey(callback, pubKey: Some("invalid pem data"), priKey: Some("invalid pem data"))
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }
}
