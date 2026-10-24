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

// The Cangjie API is in Beta. For details on its capabilities and limitations, please refer to the README file.

package ohos.security.crypto_framework

import ohos.ffi.{RemoteDataLite, releaseFFIData, safeMalloc}
import ohos.labels.APILevel
import ohos.business_exception.{BusinessException, AsyncCallback}

foreign {
    func FFiOHOSAsyKeyGeneratorConstructor(algName: CString, errCode: CPointer<Int32>): Int64

    func FFiOHOSAsyKeyGeneratorGenerateKeyPair(id: Int64, errCode: CPointer<Int32>): Int64

    func FFiOHOSAsyKeyGeneratorConvertKey(id: Int64, pubKey: CPointer<HcfBlob>, priKey: CPointer<HcfBlob>,
        errCode: CPointer<Int32>): Int64

    func FFiOHOSAsyKeyGeneratorConvertPemKey(id: Int64, pubKey: CString, priKey: CString, errCode: CPointer<Int32>): Int64

    func FFiOHOSAsyKeyGeneratorConvertPemKeyWithPassword(id: Int64, password: CString, pubKey: CString,
        priKey: CString, errCode: CPointer<Int32>): Int64
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
    unsafe {
        let cstr = LibC.mallocCString(algName)
        var errCode: Int32 = 0
        let id = FFiOHOSAsyKeyGeneratorConstructor(cstr, inout errCode)
        LibC.free(cstr)
        checkAndThrow(errCode)
        return AsyKeyGenerator(id, algName)
    }
}

/**
 * Asymmetric key generator class, defining methods for generating asymmetric keys.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class AsyKeyGenerator <: RemoteDataLite {
    private let _algName: String

    init(id: Int64, algName: String) {
        super(id)
        _algName = algName
    }

    ~init() {
        releaseFFIData(myDataId)
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public prop algName: String {
        get() {
            return _algName
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func generateKeyPair(callback: AsyncCallback<KeyPair>): Unit {
        unsafe {
            var errCode: Int32 = 0
            let id = FFiOHOSAsyKeyGeneratorGenerateKeyPair(getID(), inout errCode)
            if (errCode != 0) {
                callback(Some(BusinessException(errCode, "")), None)
                return
            }
            let keyPair = KeyPair(id, _algName)
            callback(None, keyPair)
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertKey(callback: AsyncCallback<KeyPair>, pubKey!: Option<DataBlob> = None,
        priKey!: Option<DataBlob> = None): Unit {
        unsafe {
            let pub: CPointer<HcfBlob> = match (pubKey) {
                case Some(v) =>
                    let ptr = safeMalloc<HcfBlob>()
                    let blob = HcfBlob(v)
                    ptr.write(blob)
                    ptr
                case None => CPointer<HcfBlob>()
            }
            let pri: CPointer<HcfBlob> = try {
                match (priKey) {
                    case Some(v) =>
                        let ptr = safeMalloc<HcfBlob>()
                        let blob = HcfBlob(v)
                        ptr.write(blob)
                        ptr
                    case None => CPointer<HcfBlob>()
                }
            } catch (e: Exception) {
                if (pub.isNotNull()) {
                    pub.read().free()
                    LibC.free(pub)
                }
                throw e
            }
            var errCode: Int32 = 0
            let id = FFiOHOSAsyKeyGeneratorConvertKey(getID(), pub, pri, inout errCode)
            try {
                if (errCode != 0) {
                    callback(Some(BusinessException(errCode, "")), None)
                } else {
                    let keyPair = KeyPair(id, _algName)
                    callback(None, keyPair)
                }
            } finally {
                if (pub.isNotNull()) {
                    pub.read().free()
                    LibC.free(pub)
                }
                if (pri.isNotNull()) {
                    pri.read().free()
                    LibC.free(pri)
                }
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertPemKey(callback: AsyncCallback<KeyPair>, pubKey!: Option<String> = None,
        priKey!: Option<String> = None): Unit {
        unsafe {
            let pubCStr = match (pubKey) {
                case Some(v) => LibC.mallocCString(v)
                case None => CString(CPointer<UInt8>())
            }
            let priCStr = try {
                match (priKey) {
                    case Some(v) => LibC.mallocCString(v)
                    case None => CString(CPointer<UInt8>())
                }
            } catch (e: Exception) {
                match (pubKey) {
                    case Some(_) => LibC.free(pubCStr)
                    case None => ()
                }
                throw e
            }
            var errCode: Int32 = 0
            let id = FFiOHOSAsyKeyGeneratorConvertPemKey(getID(), pubCStr, priCStr, inout errCode)
            try {
                if (errCode != 0) {
                    callback(Some(BusinessException(errCode, "")), None)
                } else {
                    let keyPair = KeyPair(id, _algName)
                    callback(None, keyPair)
                }
            } finally {
                match (pubKey) {
                    case Some(_) => LibC.free(pubCStr)
                    case None => ()
                }
                match (priKey) {
                    case Some(_) => LibC.free(priCStr)
                    case None => ()
                }
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertPemKey(password: String, callback: AsyncCallback<KeyPair>,
        pubKey!: Option<String> = None, priKey!: Option<String> = None): Unit {
        unsafe {
            let pwdCStr = LibC.mallocCString(password)
            let pubCStr = match (pubKey) {
                case Some(v) => LibC.mallocCString(v)
                case None => CString(CPointer<UInt8>())
            }
            let priCStr = try {
                match (priKey) {
                    case Some(v) => LibC.mallocCString(v)
                    case None => CString(CPointer<UInt8>())
                }
            } catch (e: Exception) {
                match (pubKey) {
                    case Some(_) => LibC.free(pubCStr)
                    case None => ()
                }
                LibC.free(pwdCStr)
                throw e
            }
            var errCode: Int32 = 0
            let id = FFiOHOSAsyKeyGeneratorConvertPemKeyWithPassword(getID(), pwdCStr, pubCStr, priCStr, inout errCode)
            try {
                if (errCode != 0) {
                    callback(Some(BusinessException(errCode, "")), None)
                } else {
                    let keyPair = KeyPair(id, _algName)
                    callback(None, keyPair)
                }
            } finally {
                match (pubKey) {
                    case Some(_) => LibC.free(pubCStr)
                    case None => ()
                }
                match (priKey) {
                    case Some(_) => LibC.free(priCStr)
                    case None => ()
                }
                LibC.free(pwdCStr)
            }
        }
    }
}
