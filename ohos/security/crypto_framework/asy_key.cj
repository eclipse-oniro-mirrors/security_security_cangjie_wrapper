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

import ohos.ffi.{RemoteDataLite, releaseFFIData}
import ohos.labels.APILevel
import ohos.business_exception.{BusinessException, ERR_PARAMETER_ERROR}
import std.math.numeric.BigInt

foreign {
    func FFiOHOSPriKeyGetAsyKeySpecByNum(id: Int64, itemType: Int32, errCode: CPointer<Int32>): IntNative

    func FFiOHOSPriKeyGetAsyKeySpecByStr(id: Int64, itemType: Int32, errCode: CPointer<Int32>): CString

    func FFiOHOSPriKeyGetAsyKeySpecByBigInt(id: Int64, itemType: Int32, errCode: CPointer<Int32>): HcfBigInteger

    func FFiOHOSPriKeyGetEncoded(id: Int64, errCode: CPointer<Int32>): HcfBlob

    func FFiOHOSPriKeyGetEncodedDer(id: Int64, format: CString, errCode: CPointer<Int32>): HcfBlob

    func FFiOHOSPriKeyGetEncodedPem(id: Int64, format: CString, errCode: CPointer<Int32>): CString

    func FFiOHOSPriKeyClearMem(id: Int64): Int32

    func FfiOHOSPriKeyGetFormat(id: Int64, errCode: CPointer<Int32>): CString

    func FFiOHOSPubKeyGetAsyKeySpecByNum(id: Int64, itemType: Int32, errCode: CPointer<Int32>): IntNative

    func FFiOHOSPubKeyGetAsyKeySpecByStr(id: Int64, itemType: Int32, errCode: CPointer<Int32>): CString

    func FFiOHOSPubKeyGetAsyKeySpecByBigInt(id: Int64, itemType: Int32, errCode: CPointer<Int32>): HcfBigInteger

    func FFiOHOSPubKeyGetEncoded(id: Int64, errCode: CPointer<Int32>): HcfBlob

    func FFiOHOSPubKeyGetEncodedDer(id: Int64, format: CString, errCode: CPointer<Int32>): HcfBlob

    func FFiOHOSPubKeyGetEncodedPem(id: Int64, format: CString, errCode: CPointer<Int32>): CString

    func FfiOHOSPubKeyGetFormat(id: Int64, errCode: CPointer<Int32>): CString

    func FfiOHOSPubKeyGetRawPointer(id: Int64): CPointer<Unit>

    func FfiOHOSPubKeyFromRawPointer(ptr: CPointer<Unit>, retString: CPointer<CPointer<UInt8>>, errCode: CPointer<Int32>): Int64

    func FFiOHOSKeyPairPubKey(id: Int64, errCode: CPointer<Int32>): Int64

    func FFiOHOSKeyPairPriKey(id: Int64, errCode: CPointer<Int32>): Int64
}

/**
 * Provides APIs for private key operations. PriKey is a child class of Key.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class PriKey <: RemoteDataLite & Key {
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
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    public prop format: String {
        get() {
            unsafe {
                var errCode: Int32 = 0
                let cstr = FfiOHOSPriKeyGetFormat(getID(), inout errCode)
                checkAndThrow(errCode)
                return cstr.toString()
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
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
    public func getAsyKeySpec(itemType: AsyKeySpecItem): ResultSpec {
        let asyKeySpecItemType = getAsyKeySpecType(itemType.value)
        if (asyKeySpecItemType == SPEC_ITEM_TYPE_BIG_INT) {
            unsafe {
                var errCode: Int32 = 0
                let returnBigInt = FFiOHOSPriKeyGetAsyKeySpecByBigInt(getID(), itemType.value, inout errCode)
                checkAndThrow(errCode)
                let res = ResultSpec.BigintValue(BigInt(true, returnBigInt.toArray()))
                returnBigInt.free()
                return res
            }
        } else if (asyKeySpecItemType == SPEC_ITEM_TYPE_NUM) {
            unsafe {
                var errCode: Int32 = 0
                let returnNum = FFiOHOSPriKeyGetAsyKeySpecByNum(getID(), itemType.value, inout errCode)
                checkAndThrow(errCode)
                return ResultSpec.Int32Value(Int32(returnNum))
            }
        } else if (asyKeySpecItemType == SPEC_ITEM_TYPE_STR) {
            unsafe {
                var errCode: Int32 = 0
                let returnString = FFiOHOSPriKeyGetAsyKeySpecByStr(getID(), itemType.value, inout errCode)
                checkAndThrow(errCode)
                let res = ResultSpec.StringValue(returnString.toString())
                LibC.free(returnString)
                return res
            }
        }
        throw BusinessException(ERR_PARAMETER_ERROR, "AsyKeySpecItem not support!")
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedDer(format: String): DataBlob {
        unsafe {
            let cformat = LibC.mallocCString(format)
            var errCode: Int32 = 0
            let returnBlob: HcfBlob = FFiOHOSPriKeyGetEncodedDer(getID(), cformat, inout errCode)
            LibC.free(cformat)
            checkAndThrow(errCode)
            let blob = returnBlob.toDataBlob()
            returnBlob.free()
            return blob
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedPem(format: String): String {
        unsafe {
            let cformat = LibC.mallocCString(format)
            var errCode: Int32 = 0
            let ret: CString = FFiOHOSPriKeyGetEncodedPem(getID(), cformat, inout errCode)
            LibC.free(cformat)
            checkAndThrow(errCode)
            let str = ret.toString()
            LibC.free(ret)
            return str
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key",
        throwexception: true
    ]
    public func getEncoded(): DataBlob {
        unsafe {
            var errCode: Int32 = 0
            let returnBlob: HcfBlob = FFiOHOSPriKeyGetEncoded(getID(), inout errCode)
            checkAndThrow(errCode)
            let blob = returnBlob.toDataBlob()
            returnBlob.free()
            return blob
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public func clearMem(): Unit {
        unsafe {
            let errCode = FFiOHOSPriKeyClearMem(getID())
            checkAndThrow(errCode)
        }
    }
}

/**
 * Provides APIs for public key operations. PubKey is a child class of Key.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class PubKey <: RemoteDataLite & Key {
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
        syscap: "SystemCapability.Security.CryptoFramework.Key"
    ]
    public prop format: String {
        get() {
            unsafe {
                var errCode: Int32 = 0
                let cstr = FfiOHOSPubKeyGetFormat(getID(), inout errCode)
                checkAndThrow(errCode)
                return cstr.toString()
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key"
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
    public func getAsyKeySpec(itemType: AsyKeySpecItem): ResultSpec {
        let asyKeySpecItemType = getAsyKeySpecType(itemType.value)
        if (asyKeySpecItemType == SPEC_ITEM_TYPE_BIG_INT) {
            unsafe {
                var errCode: Int32 = 0
                let returnBigInt = FFiOHOSPubKeyGetAsyKeySpecByBigInt(getID(), itemType.value, inout errCode)
                checkAndThrow(errCode)
                let res = ResultSpec.BigintValue(BigInt(true, returnBigInt.toArray()))
                returnBigInt.free()
                return res
            }
        } else if (asyKeySpecItemType == SPEC_ITEM_TYPE_NUM) {
            unsafe {
                var errCode: Int32 = 0
                let returnNum = FFiOHOSPubKeyGetAsyKeySpecByNum(getID(), itemType.value, inout errCode)
                checkAndThrow(errCode)
                return ResultSpec.Int32Value(Int32(returnNum))
            }
        } else if (asyKeySpecItemType == SPEC_ITEM_TYPE_STR) {
            unsafe {
                var errCode: Int32 = 0
                let returnString = FFiOHOSPubKeyGetAsyKeySpecByStr(getID(), itemType.value, inout errCode)
                checkAndThrow(errCode)
                let res = ResultSpec.StringValue(returnString.toString())
                LibC.free(returnString)
                return res
            }
        }
        throw BusinessException(ERR_PARAMETER_ERROR, "AsyKeySpecItem not support!")
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedDer(format: String): DataBlob {
        unsafe {
            let cformat = LibC.mallocCString(format)
            var errCode: Int32 = 0
            let returnBlob: HcfBlob = FFiOHOSPubKeyGetEncodedDer(getID(), cformat, inout errCode)
            LibC.free(cformat)
            checkAndThrow(errCode)
            let blob = returnBlob.toDataBlob()
            returnBlob.free()
            return blob
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func getEncodedPem(format: String): String {
        unsafe {
            let cformat = LibC.mallocCString(format)
            var errCode: Int32 = 0
            let ret: CString = FFiOHOSPubKeyGetEncodedPem(getID(), cformat, inout errCode)
            LibC.free(cformat)
            checkAndThrow(errCode)
            let str = ret.toString()
            LibC.free(ret)
            return str
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key",
        throwexception: true
    ]
    public func getEncoded(): DataBlob {
        unsafe {
            var errCode: Int32 = 0
            let returnBlob: HcfBlob = FFiOHOSPubKeyGetEncoded(getID(), inout errCode)
            checkAndThrow(errCode)
            let blob = returnBlob.toDataBlob()
            returnBlob.free()
            return blob
        }
    }

    func getRawPointer(): CPointer<Unit> {
        return unsafe { FfiOHOSPubKeyGetRawPointer(getID()) }
    }

    static func createFromRawPointer(ptr: CPointer<Unit>): PubKey {
        unsafe {
            var errCode: Int32 = 0
            var retString = CPointer<UInt8>()
            let id = FfiOHOSPubKeyFromRawPointer(ptr, inout retString, inout errCode)
            checkAndThrow(errCode)
            return PubKey(id, CString(retString).toString())
        }
    }
}

/**
 * Defines an asymmetric key pair, which includes a public key and a private key.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public class KeyPair <: RemoteDataLite {
    private let _algName: String
    private let _pubKey: ?PubKey
    private let _priKey: ?PriKey

    init(id: Int64, algName: String) {
        super(id)
        _algName = algName

        unsafe {
            var errCode: Int32 = 0
            let pubId = FFiOHOSKeyPairPubKey(getID(), inout errCode)
            _pubKey = if (errCode == 0) {
                PubKey(pubId, algName)
            } else {
                None
            }
            errCode = 0
            let priId = FFiOHOSKeyPairPriKey(getID(), inout errCode)
            _priKey = if (errCode == 0) {
                PriKey(priId, algName)
            } else {
                None
            }
        }
    }

    ~init() {
        releaseFFIData(myDataId)
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public prop pubKey: PubKey {
        get() {
            _pubKey ?? throw BusinessException(ERR_PARAMETER_ERROR, "[KeyPair] pubKey: Parameter error.")
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public prop priKey: PriKey {
        get() {
            _priKey ?? throw BusinessException(ERR_PARAMETER_ERROR, "[KeyPair] priKey: Parameter error.")
        }
    }
}
