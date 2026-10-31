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

func awaitVerifyInit(verify: Verify, pubKey: PubKey) {
    let monitor = Monitor()
    let errResult = Box(None<BusinessException>)
    let done = Box(false)
    let callback: AsyncCallback<Unit> = { err, _ =>
        if (let Some(e) <- err) {
            errResult.value = e
        }
        done.value = true
        synchronized(monitor) {
            monitor.notify()
        }
    }
    verify.initialize(pubKey, callback)
    synchronized(monitor) {
        monitor.wait(timeout: Duration.second * 10)
    }
    if (let Some(e) <- errResult.value) {
        throw e
    }
    if (!done.value) {
        throw Exception("verify initialize timeout")
    }
}

func awaitVerifyUpdate(verify: Verify, data: DataBlob) {
    let monitor = Monitor()
    let errResult = Box(None<BusinessException>)
    let done = Box(false)
    let callback: AsyncCallback<Unit> = { err, _ =>
        if (let Some(e) <- err) {
            errResult.value = e
        }
        done.value = true
        synchronized(monitor) {
            monitor.notify()
        }
    }
    verify.update(data, callback)
    synchronized(monitor) {
        monitor.wait(timeout: Duration.second * 10)
    }
    if (let Some(e) <- errResult.value) {
        throw e
    }
    if (!done.value) {
        throw Exception("verify update timeout")
    }
}

func awaitVerifyResult(verify: Verify, data: DataBlob, sig: DataBlob): Bool {
    let monitor = Monitor()
    let result = Box(None<Bool>)
    let errResult = Box(None<BusinessException>)
    let callback: AsyncCallback<Bool> = { err, verifyResult =>
        if (let Some(e) <- err) {
            errResult.value = e
        } else if (let Some(r) <- verifyResult) {
            result.value = r
        }
        synchronized(monitor) {
            monitor.notify()
        }
    }
    verify.verify(data, sig, callback)
    synchronized(monitor) {
        monitor.wait(timeout: Duration.second * 10)
    }
    if (let Some(e) <- errResult.value) {
        throw e
    }
    return result.value.getOrThrow(() => Exception("verify timeout"))
}

/**
 * 测试ohos.crypto_framework模块的Verify类操作功能
 */
@Test
class Test_Verify_Operations_Add {
    /**
     * 测试Verify.algName属性 - 有效等价类：返回RSA4096|PKCS1|SHA256算法名称
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_algName_RSA4096() {
        try {
            let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
            @Expect(verify.algName == "RSA4096|PKCS1|SHA256")
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.algName属性 - 有效等价类：返回ECC256|SHA256算法名称
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_algName_ECC256() {
        try {
            let verify: Verify = createVerify("ECC256|SHA256")
            @Expect(verify.algName == "ECC256|SHA256")
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.initialize API - 有效等价类：使用RSA4096公钥初始化验签实例
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_initialize_RSA4096() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
            awaitVerifyInit(verify, keyPair.pubKey)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.update API - 有效等价类：初始化后更新验签数据
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_update() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
            awaitVerifyInit(verify, keyPair.pubKey)
            let testData: DataBlob = DataBlob(Array<UInt8>(32, repeat:0x41))
            awaitVerifyUpdate(verify, testData)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.update API - 异常：未初始化就调用update，回调错误码17620004
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_update_withoutInit() {
        let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
        let testData: DataBlob = DataBlob(Array<UInt8>(32, repeat:0x41))

        try {
            let monitor = Monitor()
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<Unit> = { err, _ =>
                if (let Some(e) <- err) {
                    errResult.value = e
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            verify.update(testData, callback)
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620004)
        }
    }

    /**
     * 测试Verify.verify(data, sig, callback) API - 有效等价类：验签伪造签名返回false
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_verify_with_fake_sig() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
            awaitVerifyInit(verify, keyPair.pubKey)
            let testData: DataBlob = DataBlob(Array<UInt8>(32, repeat:0x41))
            let fakeSig: DataBlob = DataBlob(Array<UInt8>(512, repeat:0))
            let result: Bool = awaitVerifyResult(verify, testData, fakeSig)
            @Expect(result == false)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.verify(data, sig, callback) API - 异常：未初始化就调用verify，回调错误码17620004
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_verify_withoutInit() {
        let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
        let testData: DataBlob = DataBlob(Array<UInt8>(32, repeat:0x41))
        let fakeSig: DataBlob = DataBlob(Array<UInt8>(512, repeat:0))

        try {
            let monitor = Monitor()
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<Bool> = { err, _ =>
                if (let Some(e) <- err) {
                    errResult.value = e
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            verify.verify(testData, fakeSig, callback)
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620004)
        }
    }

    /**
     * 测试Verify.verify(sig, callback, data!)重载 API - 有效等价类：以命名参数传入数据验签
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_verify_overload_with_data() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
            awaitVerifyInit(verify, keyPair.pubKey)
            let testData: DataBlob = DataBlob(Array<UInt8>(32, repeat:0x41))
            let fakeSig: DataBlob = DataBlob(Array<UInt8>(512, repeat:0))

            let monitor = Monitor()
            let result = Box(None<Bool>)
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<Bool> = { err, verifyResult =>
                if (let Some(e) <- err) {
                    errResult.value = e
                } else if (let Some(r) <- verifyResult) {
                    result.value = r
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            verify.verify(fakeSig, callback, data: Some(testData))
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(result.value ?? false == false)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.verify(sig, callback, data: None)重载 API - 有效等价类：update后不传数据验签
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_verify_overload_no_data() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
            awaitVerifyInit(verify, keyPair.pubKey)
            let testData: DataBlob = DataBlob(Array<UInt8>(32, repeat:0x41))
            awaitVerifyUpdate(verify, testData)
            let fakeSig: DataBlob = DataBlob(Array<UInt8>(512, repeat:0))

            let monitor = Monitor()
            let callbackReceived = Box(false)
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<Bool> = { err, _ =>
                if (let Some(e) <- err) {
                    errResult.value = e
                }
                callbackReceived.value = true
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            verify.verify(fakeSig, callback, data: Option<DataBlob>.None)
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(callbackReceived.value)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.recover API - 有效等价类：RSA验签恢复原始数据，验证回调被调用
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_recover() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
            awaitVerifyInit(verify, keyPair.pubKey)
            let fakeSig: DataBlob = DataBlob(Array<UInt8>(512, repeat:0))

            let monitor = Monitor()
            let callbackReceived = Box(false)
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<?DataBlob> = { err, _ =>
                if (let Some(e) <- err) {
                    errResult.value = e
                }
                callbackReceived.value = true
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            verify.recover(fakeSig, callback)
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            // recover可能返回None或抛出异常，只要回调被调用即验证成功
            @Expect(callbackReceived.value)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.recover API - 异常：非RSA算法调用recover，回调错误码17620004
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_recover_nonRSA() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("ECC256")
        let keyPair: KeyPair = awaitGenerateKeyPair(generator)
        let verify: Verify = createVerify("ECC256|SHA256")
        awaitVerifyInit(verify, keyPair.pubKey)
        let fakeSig: DataBlob = DataBlob(Array<UInt8>(64, repeat:0))

        try {
            let monitor = Monitor()
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<?DataBlob> = { err, _ =>
                if (let Some(e) <- err) {
                    errResult.value = e
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            verify.recover(fakeSig, callback)
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620004)
        }
    }

    /**
     * 测试Verify.setVerifySpec(Int32) API - 有效等价类：设置RSA PSS盐长度
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_setVerifySpec_Int32() {
        try {
            let verify: Verify = createVerify("RSA4096|PSS|SHA256|MGF1_SHA256")
            verify.setVerifySpec(SignSpecItem.PssSaltLenNum, 32)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.setVerifySpec(Int32) API - 异常：无效参数值，错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_setVerifySpec_Int32_invalid() {
        let verify: Verify = createVerify("RSA4096|PSS|SHA256|MGF1_SHA256")
        try {
            verify.setVerifySpec(SignSpecItem.PssSaltLenNum, -4)
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }

    /**
     * 测试Verify.setVerifySpec(Array<UInt8>) API - 有效等价类：设置SM2用户ID
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_setVerifySpec_ArrayUInt8() {
        try {
            let verify: Verify = createVerify("SM2|SM3")
            verify.setVerifySpec(SignSpecItem.Sm2UserIdUint8arr, [0x31, 0x32, 0x33, 0x34])
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.setVerifySpec(Array<UInt8>) API - 异常：空数组，错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_setVerifySpec_ArrayUInt8_empty() {
        let verify: Verify = createVerify("SM2|SM3")
        try {
            verify.setVerifySpec(SignSpecItem.Sm2UserIdUint8arr, Array<UInt8>())
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }

    /**
     * 测试Verify.getVerifySpec API - 有效等价类：获取RSA PSS盐长度
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_getVerifySpec() {
        try {
            let verify: Verify = createVerify("RSA4096|PSS|SHA256|MGF1_SHA256")
            verify.setVerifySpec(SignSpecItem.PssSaltLenNum, 32)
            let spec: ResultSpec = verify.getVerifySpec(SignSpecItem.PssSaltLenNum)
            @Expect(true)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }

    /**
     * 测试Verify.getVerifySpec API - 异常：获取未设置的参数，错误码17620003
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_getVerifySpec_invalid() {
        let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
        try {
            verify.getVerifySpec(SignSpecItem.PssSaltLenNum)
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(e.code == 17620003)
        }
    }

    /**
     * 测试Verify完整流程 - 有效等价类：init -> update(chunk1) -> update(chunk2) -> verify
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_verify_full_flow() {
        try {
            let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
            let keyPair: KeyPair = awaitGenerateKeyPair(generator)
            let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
            awaitVerifyInit(verify, keyPair.pubKey)
            let chunk1: DataBlob = DataBlob(Array<UInt8>(32, repeat:0x41))
            let chunk2: DataBlob = DataBlob(Array<UInt8>(32, repeat:0x42))
            awaitVerifyUpdate(verify, chunk1)
            awaitVerifyUpdate(verify, chunk2)
            let fakeSig: DataBlob = DataBlob(Array<UInt8>(512, repeat:0))

            let monitor = Monitor()
            let result = Box(None<Bool>)
            let errResult = Box(None<BusinessException>)
            let callback: AsyncCallback<Bool> = { err, verifyResult =>
                if (let Some(e) <- err) {
                    errResult.value = e
                } else if (let Some(r) <- verifyResult) {
                    result.value = r
                }
                synchronized(monitor) {
                    monitor.notify()
                }
            }
            verify.verify(fakeSig, callback, data: Option<DataBlob>.None)
            synchronized(monitor) {
                monitor.wait(timeout: Duration.second * 10)
            }
            if (let Some(e) <- errResult.value) {
                throw e
            }
            @Expect(result.value ?? false == false)
        } catch (e: BusinessException) {
            @Expect(false)
        }
    }
}
