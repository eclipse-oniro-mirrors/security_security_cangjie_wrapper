/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

// The Cangjie API is in Beta. For details on its capabilities and limitations, please refer to the README file.

package ohos.security.crypto_framework

import ohos.labels.APILevel

/**
 * Signature verification class, defining methods for verifying signatures using a public key.
 */
@!APILevel[
    since: "26.0.1",
    syscap: "SystemCapability.Security.CryptoFramework.Signature"
]
public class Verify {
    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    public prop algName: String {
        get() { return String() }
    }

    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func initialize(pubKey: PubKey, callback: AsyncCallback<Unit>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func update(data: DataBlob, callback: AsyncCallback<Unit>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func verify(data: DataBlob, signatureData: DataBlob, callback: AsyncCallback<Bool>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func verify(data: ?DataBlob, signatureData: DataBlob, callback: AsyncCallback<Bool>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func recover(signatureData: DataBlob, callback: AsyncCallback<?DataBlob>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func setVerifySpec(itemType: SignSpecItem, itemValue: Int32): Unit {
        return ()
    }

    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func setVerifySpec(itemType: SignSpecItem, itemValue: Array<UInt8>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.0.1",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func getVerifySpec(itemType: SignSpecItem): ResultSpec {
        return ResultSpec.STRING(String())
    }

    public init() {
        super()
    }
}

/**
 * Creates a Verify instance.
 */
@!APILevel[
    since: "26.0.1",
    syscap: "SystemCapability.Security.CryptoFramework.Signature",
    throwexception: true
]
public func createVerify(algName: String): Verify {
    return Verify()
}
