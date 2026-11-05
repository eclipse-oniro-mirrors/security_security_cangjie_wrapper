/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

package ohos.security.crypto_framework

import ohos.labels.APILevel
import ohos.business_exception.AsyncCallback

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher",
    throwexception: true
]
public func createCipher(transformation: String): Cipher {
    return Cipher()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public class Cipher {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public prop algName: String {
        
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher",
        throwexception: true
    ]
    public func initialize(opMode: CryptoMode, key: Key, params: ?ParamsSpec): Unit {
        return ()
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher",
        throwexception: true,
        workerthread: true
    ]
    public func update(data: DataBlob): DataBlob {
        return DataBlob(Array())
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher",
        throwexception: true,
        workerthread: true
    ]
    public func doFinal(data: ?DataBlob): DataBlob {
        return DataBlob(Array())
    }
    
    public init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework"
]
public class DataBlob {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public var data: Array<UInt8>

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public init(data: Array<UInt8>) {
        super()
        this.data = Array()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public class IvParamsSpec <: ParamsSpec {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var iv: DataBlob

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public init(algName: String, iv: DataBlob) {
        super()
        this.iv = DataBlob(Array())
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public class GcmParamsSpec <: ParamsSpec {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var aad: DataBlob

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var iv: DataBlob

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var authTag: DataBlob

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public init(algName: String, iv: DataBlob, aad: DataBlob, authTag: DataBlob) {
        super()
        this.aad = DataBlob(Array())
        this.iv = DataBlob(Array())
        this.authTag = DataBlob(Array())
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public class CcmParamsSpec <: ParamsSpec {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var authTag: DataBlob

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var aad: DataBlob

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var iv: DataBlob

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public init(algName: String, iv: DataBlob, aad: DataBlob, authTag: DataBlob) {
        super()
        this.authTag = DataBlob(Array())
        this.aad = DataBlob(Array())
        this.iv = DataBlob(Array())
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public enum CryptoMode {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    EncryptMode
    |
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    DecryptMode
    | ...
}

extend CryptoMode <: ToString {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public func toString(): String {
        return String()
    }
}

extend CryptoMode <: Equatable<CryptoMode> {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public operator func ==(other: CryptoMode): Bool {
        return true
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public operator func !=(other: CryptoMode): Bool {
        return true
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public enum CipherSpecItem {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    OaepMdNameStr
    |
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    OaepMgfNameStr
    |
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    OaepMgf1MdStr
    |
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    OaepMgf1PsrcUint8Arr
    | ...
}

extend CipherSpecItem <: ToString {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public func toString(): String {
        return String()
    }
}

extend CipherSpecItem <: Equatable<CipherSpecItem> {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public operator func ==(other: CipherSpecItem): Bool {
        return true
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public operator func !=(other: CipherSpecItem): Bool {
        return true
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Key"
]
public interface Key {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    prop format: String

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    prop algName: String

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key",
        throwexception: true
    ]
    func getEncoded(): DataBlob
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Cipher"
]
public open class ParamsSpec {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Cipher"
    ]
    public var algName: String
    
    public init() {
        super()
        this.algName = String()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Mac",
    throwexception: true
]
public func createMac(algName: String): Mac {
    return Mac()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Mac"
]
public class Mac {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac"
    ]
    public prop algName: String {
        
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac",
        throwexception: true
    ]
    public func initialize(key: SymKey): Unit {
        return ()
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac",
        throwexception: true,
        workerthread: true
    ]
    public func update(input: DataBlob): Unit {
        return ()
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac",
        throwexception: true,
        workerthread: true
    ]
    public func doFinal(): DataBlob {
        return DataBlob(Array())
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Mac",
        throwexception: true
    ]
    public func getMacLength(): UInt32 {
        return 0
    }
    
    public init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.MessageDigest",
    throwexception: true
]
public func createMd(algName: String): Md {
    return Md()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.MessageDigest"
]
public class Md {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.MessageDigest"
    ]
    public prop algName: String {
        
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.MessageDigest",
        throwexception: true
    ]
    public func update(input: DataBlob): Unit {
        return ()
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.MessageDigest",
        throwexception: true,
        workerthread: true
    ]
    public func digest(): DataBlob {
        return DataBlob(Array())
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.MessageDigest",
        throwexception: true
    ]
    public func getMdLength(): UInt32 {
        return 0
    }
    
    public init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Rand",
    throwexception: true
]
public func createRandom(): Random {
    return Random()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Rand"
]
public class Random {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Rand"
    ]
    public prop algName: String {
        
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Rand",
        throwexception: true
    ]
    public func generateRandom(len: Int32): DataBlob {
        return DataBlob(Array())
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Rand",
        throwexception: true
    ]
    public func setSeed(seed: DataBlob): Unit {
        return ()
    }
    
    public init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey"
]
public class SymKey <: Key {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey"
    ]
    public prop algName: String {
        
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey"
    ]
    public prop format: String {
        
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey",
        throwexception: true
    ]
    public func getEncoded(): DataBlob {
        return DataBlob(Array())
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey"
    ]
    public func clearMem(): Unit {
        return ()
    }
    
    public init() {
        super()
    }
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey",
    throwexception: true
]
public func createSymKeyGenerator(algName: String): SymKeyGenerator {
    return SymKeyGenerator()
}

@!APILevel[
    since: "22",
    syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey"
]
public class SymKeyGenerator {
    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey"
    ]
    public prop algName: String {
        
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey",
        throwexception: true,
        workerthread: true
    ]
    public func generateSymKey(): SymKey {
        return SymKey()
    }

    @!APILevel[
        since: "22",
        syscap: "SystemCapability.Security.CryptoFramework.Key.SymKey",
        throwexception: true,
        workerthread: true
    ]
    public func convertKey(key: DataBlob): SymKey {
        return SymKey()
    }

    public init() {
        super()
    }
}

@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
    throwexception: true
]
public func createAsyKeyGenerator(algName: String): AsyKeyGenerator {
    return AsyKeyGenerator()
}

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
        get() {
            return String()
        }
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
    public func convertKey(callback: AsyncCallback<KeyPair>, pubKey!: Option<DataBlob> = None,
        priKey!: Option<DataBlob> = None): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertPemKey(callback: AsyncCallback<KeyPair>, pubKey!: Option<String> = None,
        priKey!: Option<String> = None): Unit {
        return ()
    }
}

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
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    public prop algName: String {
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getAsyKeySpec(itemType: AsyKeySpecItem): ResultSpec {
        return ResultSpec.StringValue(String())
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

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public func clearMem(): Unit {
        return ()
    }
}

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
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    public prop algName: String {
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getAsyKeySpec(itemType: AsyKeySpecItem): ResultSpec {
        return ResultSpec.StringValue(String())
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

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public func clearMem(): Unit {
        return ()
    }
}

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
        get() {
            return PriKey()
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public prop pubKey: PubKey {
        get() {
            return PubKey()
        }
    }
}

@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Signature",
    throwexception: true
]
public func createVerify(algName: String): Verify {
    return Verify()
}

@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Signature"
]
public class Verify {
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    public prop algName: String {
        get() {
            return String()
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func initialize(pubKey: PubKey, callback: AsyncCallback<Unit>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func update(data: DataBlob, callback: AsyncCallback<Unit>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func verify(data: DataBlob, signatureData: DataBlob, callback: AsyncCallback<Bool>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func verify(signatureData: DataBlob, callback: AsyncCallback<Bool>,
        data!: Option<DataBlob> = None): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func recover(signatureData: DataBlob, callback: AsyncCallback<?DataBlob>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func setVerifySpec(itemType: SignSpecItem, itemValue: Int32): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func setVerifySpec(itemType: SignSpecItem, itemValue: Array<UInt8>): Unit {
        return ()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func getVerifySpec(itemType: SignSpecItem): ResultSpec {
        return ResultSpec.StringValue(String())
    }
}

@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Signature"
]
public enum SignSpecItem {
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssMdNameStr
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssMgfNameStr
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssMgf1MdStr
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssSaltLenNum
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssTrailerFieldNum
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    Sm2UserIdUint8arr
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    MlDsaDeterministicBool
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    MlDsaMuBool
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    MlDsaContextUint8arr
    | ...
}

@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public enum AsyKeySpecItem {
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaPBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaQBn
    | ...
}

@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework"
]
public enum ResultSpec {
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    BigintValue(Int64)
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    Int32Value(Int32)
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    StringValue(String)
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    Uint8ArrayValue(Array<UInt8>)
    | ...
}
