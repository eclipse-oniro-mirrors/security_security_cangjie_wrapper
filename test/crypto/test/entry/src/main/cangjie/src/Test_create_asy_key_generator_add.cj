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
 * 测试ohos.crypto_framework模块的createAsyKeyGenerator和createVerify API功能
 */
@Test
class Test_Create_Asy_Key_Generator_Add {
    /**
     * 测试createAsyKeyGenerator API - 有效等价类：创建RSA密钥生成器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createAsyKeyGenerator_RSA4096() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("RSA4096")
        @Expect(generator.algName == "RSA4096")
    }

    /**
     * 测试createAsyKeyGenerator API - 有效等价类：创建ECC密钥生成器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createAsyKeyGenerator_ECC256() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("ECC256")
        @Expect(generator.algName == "ECC256")
    }

    /**
     * 测试createAsyKeyGenerator API - 有效等价类：创建Ed25519密钥生成器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createAsyKeyGenerator_Ed25519() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("Ed25519")
        @Expect(generator.algName == "Ed25519")
    }

    /**
     * 测试createAsyKeyGenerator API - 有效等价类：创建X25519密钥生成器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createAsyKeyGenerator_X25519() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("X25519")
        @Expect(generator.algName == "X25519")
    }

    /**
     * 测试createAsyKeyGenerator API - 有效等价类：创建SM2密钥生成器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createAsyKeyGenerator_SM2() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("SM2")
        @Expect(generator.algName == "SM2")
    }

    /**
     * 测试createAsyKeyGenerator API - 有效等价类：创建DSA密钥生成器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createAsyKeyGenerator_DSA2048() {
        let generator: AsyKeyGenerator = createAsyKeyGenerator("DSA2048")
        @Expect(generator.algName == "DSA2048")
    }

    /**
     * 测试createAsyKeyGenerator API - 无效等价类：空算法名称
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createAsyKeyGenerator_empty() {
        try {
            createAsyKeyGenerator("")
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(true)
        }
    }

    /**
     * 测试createAsyKeyGenerator API - 无效等价类：无效的算法名称
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createAsyKeyGenerator_invalid() {
        try {
            createAsyKeyGenerator("INVALID_ALG")
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(true)
        }
    }

    /**
     * 测试createVerify API - 有效等价类：创建RSA验签器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createVerify_RSA4096() {
        let verify: Verify = createVerify("RSA4096|PKCS1|SHA256")
        @Expect(verify.algName == "RSA4096|PKCS1|SHA256")
    }

    /**
     * 测试createVerify API - 有效等价类：创建ECC验签器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createVerify_ECC256() {
        let verify: Verify = createVerify("ECC256|SHA256")
        @Expect(verify.algName == "ECC256|SHA256")
    }

    /**
     * 测试createVerify API - 有效等价类：创建Ed25519验签器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createVerify_Ed25519() {
        let verify: Verify = createVerify("Ed25519")
        @Expect(verify.algName == "Ed25519")
    }

    /**
     * 测试createVerify API - 有效等价类：创建SM2验签器
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createVerify_SM2() {
        let verify: Verify = createVerify("SM2|SM3")
        @Expect(verify.algName == "SM2|SM3")
    }

    /**
     * 测试createVerify API - 无效等价类：空算法名称
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createVerify_empty() {
        try {
            createVerify("")
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(true)
        }
    }

    /**
     * 测试createVerify API - 无效等价类：无效的算法名称
     */
    @TestCase
    @Tag[APILevel26_1, TestLevel0]
    func test_createVerify_invalid() {
        try {
            createVerify("INVALID_ALG")
            @Expect(false)
        } catch (e: BusinessException) {
            @Expect(true)
        }
    }
}
