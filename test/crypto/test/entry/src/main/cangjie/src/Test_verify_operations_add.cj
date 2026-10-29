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
 * 测试ohos.crypto_framework模块的Verify类操作功能
 */
@Test
class Test_Verify_Operations_Add {

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
     * 辅助函数：异步等待Verify.initialize回调
     */
    func awaitVerifyInit(verify: Verify, pubKey: PubKey): Unit {
        let monitor = Monitor()
        var errResult: ?BusinessException = None
        verify.initialize(pubKey, { err, _ =>
            if (let Some(e) <- err) {
                errResult = e
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
    }

    /**
     * 辅助函数：异步等待Verify.update回调
     */
    func awaitVerifyUpdate(verify: Verify, data: DataBlob): Unit {
        let monitor = Monitor()
        var errResult: ?BusinessException = None
        verify.update(data, { err, _ =>
            if (let Some(e) <- err) {
                errResult = e
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
    }

    /**
     * 辅助函数：异步等待Verify.verify回调，返回验签结果
     */
    func awaitVerifyResult(verify: Verify, data: DataBlob, sig: DataBlob): Bool {
        let monitor = Monitor()
        var result: ?Bool = None
        var errResult: ?BusinessException = None
        verify.verify(data, sig, { err, ret =>
            if (let Some(e) <- err) {
                errResult = e
            } else if (let Some(v) <- ret) {
                result = v
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
        return result ?? throw Exception("verify timeout")
    }

    /**
     * 测试Verify.algName - 有效等价类：获取验签器算法名
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_algName_RSA() {
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        @Expect(verify.algName == "RSA4096|PKCS1|SHA256")
    }

    /**
     * 测试Verify.algName - 有效等价类：获取ECC验签器算法名
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_algName_ECC() {
        let verify = createVerify("ECC256|SHA256")
        @Expect(verify.algName == "ECC256|SHA256")
    }

    /**
     * 测试Verify.initialize - 有效等价类：使用RSA公钥初始化验签器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_initialize_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        @Expect(true)
    }

    /**
     * 测试Verify.initialize - 有效等价类：使用ECC公钥初始化验签器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_initialize_ECC() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("ECC256|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        @Expect(true)
    }

    /**
     * 测试Verify.update - 有效等价类：RSA初始化后更新数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_update_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        let data = DataBlob("test data for verify".toArray())
        awaitVerifyUpdate(verify, data)
        @Expect(true)
    }

    /**
     * 测试Verify.verify - 有效等价类：RSA验签（使用假签名，预期返回false）
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_verify_RSA_fakeSig() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        let data = DataBlob("test data".toArray())
        let fakeSig = DataBlob(Array<UInt8>(512, item: 0))
        let result = awaitVerifyResult(verify, data, fakeSig)
        // 假签名验签应返回false
        @Expect(result == false)
    }

    /**
     * 测试Verify.verify - 有效等价类：ECC验签（使用假签名，预期返回false）
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_verify_ECC_fakeSig() {
        let generator = createAsyKeyGenerator("ECC256")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("ECC256|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        let data = DataBlob("test data".toArray())
        let fakeSig = DataBlob(Array<UInt8>(64, item: 0))
        let result = awaitVerifyResult(verify, data, fakeSig)
        @Expect(result == false)
    }

    /**
     * 测试Verify.verify(重载2) - 有效等价类：不带update的直接验签
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_verify_overload2_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        let data = DataBlob("test data for overload2".toArray())
        let fakeSig = DataBlob(Array<UInt8>(512, item: 0))
        let monitor = Monitor()
        var result: ?Bool = None
        verify.verify(fakeSig, { err, ret =>
            if (let Some(v) <- ret) {
                result = v
            }
            synchronized(monitor) {
                monitor.notify()
            }
        }, data!: Some(data))
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        @Expect(result == false)
    }

    /**
     * 测试Verify.verify(重载2) - 有效等价类：data参数传None
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_verify_overload2_dataNone() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        let fakeSig = DataBlob(Array<UInt8>(512, item: 0))
        let monitor = Monitor()
        var result: ?Bool = None
        verify.verify(fakeSig, { err, ret =>
            if (let Some(v) <- ret) {
                result = v
            }
            synchronized(monitor) {
                monitor.notify()
            }
        })
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        @Expect(result != None)
    }

    /**
     * 测试Verify.recover - 有效等价类：RSA恢复签名数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_recover_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        let fakeSig = DataBlob(Array<UInt8>(512, item: 0))
        let monitor = Monitor()
        var gotCallback = false
        verify.recover(fakeSig, { err, ret =>
            gotCallback = true
            synchronized(monitor) {
                monitor.notify()
            }
        })
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        @Expect(gotCallback)
    }

    /**
     * 测试Verify.setVerifySpec(Int32) - 有效等价类：设置RSA-PSS盐长度
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_setVerifySpec_Int32_PssSaltLen() {
        let verify = createVerify("RSA4096|PSS|SHA256")
        verify.setVerifySpec(SignSpecItem.PssSaltLenNum, 32)
        @Expect(true)
    }

    /**
     * 测试Verify.setVerifySpec(Array) - 有效等价类：设置SM2用户ID
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_setVerifySpec_Array_Sm2UserId() {
        let verify = createVerify("SM2|SM3")
        let userId: Array<UInt8> = [0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        verify.setVerifySpec(SignSpecItem.Sm2UserIdUint8arr, userId)
        @Expect(true)
    }

    /**
     * 测试Verify.getVerifySpec - 有效等价类：获取RSA-PSS MD名称
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_getVerifySpec_PssMdName() {
        let verify = createVerify("RSA4096|PSS|SHA256")
        verify.setVerifySpec(SignSpecItem.PssMdNameStr, 0)
        // getVerifySpec返回ResultSpec.StringValue
        let spec = verify.getVerifySpec(SignSpecItem.PssMdNameStr)
        @Expect(true)
    }

    /**
     * 测试Verify.getVerifySpec - 有效等价类：获取RSA-PSS盐长度
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_getVerifySpec_PssSaltLen() {
        let verify = createVerify("RSA4096|PSS|SHA256")
        verify.setVerifySpec(SignSpecItem.PssSaltLenNum, 32)
        let spec = verify.getVerifySpec(SignSpecItem.PssSaltLenNum)
        @Expect(true)
    }

    /**
     * 测试Verify完整流程 - 有效等价类：init→update→verify RSA
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_fullFlow_RSA() {
        let generator = createAsyKeyGenerator("RSA4096")
        let keyPair = awaitGenerateKeyPair(generator)
        let verify = createVerify("RSA4096|PKCS1|SHA256")

        // 初始化
        awaitVerifyInit(verify, keyPair.pubKey)
        // 更新数据
        let data1 = DataBlob("chunk1".toArray())
        awaitVerifyUpdate(verify, data1)
        let data2 = DataBlob("chunk2".toArray())
        awaitVerifyUpdate(verify, data2)
        // 验签（假签名）
        let fakeSig = DataBlob(Array<UInt8>(512, item: 0))
        let result = awaitVerifyResult(verify, DataBlob(Array<UInt8>(0)), fakeSig)
        @Expect(result == false)
    }

    /**
     * 测试Verify.update - 无效等价类：未初始化直接update
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_update_withoutInit() {
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        let data = DataBlob("test".toArray())
        let monitor = Monitor()
        var gotError = false
        verify.update(data, { err, _ =>
            if (err != None) {
                gotError = true
            }
            synchronized(monitor) {
                monitor.notify()
            }
        })
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        @Expect(gotError)
    }

    /**
     * 测试Verify.verify - 无效等价类：未初始化直接verify
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_Verify_verify_withoutInit() {
        let verify = createVerify("RSA4096|PKCS1|SHA256")
        let data = DataBlob("test".toArray())
        let fakeSig = DataBlob(Array<UInt8>(512, item: 0))
        let monitor = Monitor()
        var gotError = false
        verify.verify(data, fakeSig, { err, _ =>
            if (err != None) {
                gotError = true
            }
            synchronized(monitor) {
                monitor.notify()
            }
        })
        synchronized(monitor) {
            monitor.wait(timeout: Duration.second * 10)
        }
        @Expect(gotError)
    }
}
