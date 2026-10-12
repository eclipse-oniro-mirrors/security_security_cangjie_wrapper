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

import ohos.business_exception.AsyncCallback
import ohos.labels.APILevel

/**
 * Encapsulates the parameters used for encrypting private keys.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class KeyEncodingConfig {
    private var _password: String = String()

    private var _cipherName: String = String()

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public mut prop password: String {
        get() { return _password }
        set(v) { _password = v }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public mut prop cipherName: String {
        get() { return _cipherName }
        set(v) { _cipherName = v }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public init() {
        super()
        _password = String()
        _cipherName = String()
    }
}

/**
 * Provides APIs for private key operations. PriKey is a child class of Key.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class PriKey <: Key {
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    public prop format: String {
        get() { return String() }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    public prop algName: String {
        get() { return String() }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public func clearMem(): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getAsyKeySpec(itemType: AsyKeySpecItem): ResultSpec {
        return ResultSpec.NUMBER(0)
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedDer(format: String): DataBlob {
        return DataBlob(Array())
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedPem(format: String): String {
        return String()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedPem(format: String, config: KeyEncodingConfig): String {
        return String()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key",
        throwexception: true
    ]
    public func getEncoded(): DataBlob {
        return DataBlob(Array())
    }

    public init() {
        super()
    }
}

/**
 * Provides APIs for public key operations. PubKey is a child class of Key.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class PubKey <: Key {
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    public prop format: String {
        get() { return String() }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    public prop algName: String {
        get() { return String() }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getAsyKeySpec(itemType: AsyKeySpecItem): ResultSpec {
        return ResultSpec.NUMBER(0)
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedDer(format: String): DataBlob {
        return DataBlob(Array())
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedPem(format: String): String {
        return String()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key",
        throwexception: true
    ]
    public func getEncoded(): DataBlob {
        return DataBlob(Array())
    }

    public init() {
        super()
    }
}

/**
 * Defines an asymmetric key pair, which includes a public key and a private key.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class KeyPair {
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public prop priKey: PriKey {
        get() { return PriKey() }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public prop pubKey: PubKey {
        get() { return PubKey() }
    }

    public init() {
        super()
    }
}

/**
 * Asymmetric key generator class, defining methods for generating asymmetric keys.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class AsyKeyGenerator {
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public prop algName: String {
        get() { return String() }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func generateKeyPair(callback: AsyncCallback<KeyPair>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertKey(pubKey: DataBlob, priKey: DataBlob, callback: AsyncCallback<KeyPair>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertKey(pubKey: ?DataBlob, priKey: ?DataBlob, callback: AsyncCallback<KeyPair>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertPemKey(pubKey: ?String, priKey: ?String, callback: AsyncCallback<KeyPair>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertPemKey(pubKey: ?String, priKey: ?String, password: String, callback: AsyncCallback<KeyPair>): Unit {
        return ()
    }

    public init() {
        super()
    }
}

/**
 * Creates an AsyKeyGenerator instance based on the specified algorithm.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
    throwexception: true
]
public func createAsyKeyGenerator(algName: String): AsyKeyGenerator {
    return AsyKeyGenerator()
}
