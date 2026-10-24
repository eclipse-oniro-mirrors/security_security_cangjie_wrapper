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

import ohos.ffi.{RemoteDataLite, releaseFFIData, safeMalloc}
import ohos.labels.APILevel
import ohos.business_exception.{BusinessException, AsyncCallback, ERR_PARAMETER_ERROR}

foreign {
    func FFiOHOSVerifyConstructor(algName: CString, errCode: CPointer<Int32>): Int64

    func FFiOHOSVerifyInit(vid: Int64, pid: Int64): Int32

    func FFiOHOSVerifyUpdate(id: Int64, data: HcfBlob): Int32

    func FFiOHOSVerifyVerify(id: Int64, data: CPointer<HcfBlob>, signatureData: HcfBlob, errCode: CPointer<Int32>): Bool

    func FFiOHOSVerifyRecover(id: Int64, input: HcfBlob, output: CPointer<HcfBlob>): Int32

    func FFiOHOSVerifySetVerifySpecByNum(id: Int64, itemValue: Int32): Int32

    func FFiOHOSVerifySetVerifySpecByArr(id: Int64, itemValue: HcfBlob): Int32

    func FFiOHOSVerifyGetVerifySpecString(id: Int64, item: Int32, errCode: CPointer<Int32>): CString

    func FFiOHOSVerifyGetVerifySpecNum(id: Int64, item: Int32, itemValue: CPointer<Int32>): Int32
}

/**
 * Creates a Verify instance.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Signature",
    throwexception: true
]
public func createVerify(algName: String): Verify {
    unsafe {
        let cstr = LibC.mallocCString(algName)
        var errCode: Int32 = 0
        let id = FFiOHOSVerifyConstructor(cstr, inout errCode)
        LibC.free(cstr)
        checkAndThrow(errCode)
        return Verify(id, algName)
    }
}

/**
 * Signature verification class, defining methods for verifying signatures using a public key.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Signature"
]
public class Verify <: RemoteDataLite {
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
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    public prop algName: String {
        get() {
            return _algName
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func initialize(pubKey: PubKey, callback: AsyncCallback<Unit>): Unit {
        unsafe {
            let errCode = FFiOHOSVerifyInit(getID(), pubKey.getID())
            if (errCode != 0) {
                callback(Some(BusinessException(errCode, "")), None)
            } else {
                callback(None, ())
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func update(data: DataBlob, callback: AsyncCallback<Unit>): Unit {
        unsafe {
            let blob = HcfBlob(data)
            let errCode = FFiOHOSVerifyUpdate(getID(), blob)
            blob.free()
            if (errCode != 0) {
                callback(Some(BusinessException(errCode, "")), None)
            } else {
                callback(None, ())
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func verify(data: DataBlob, signatureData: DataBlob, callback: AsyncCallback<Bool>): Unit {
        unsafe {
            let dataBlob: CPointer<HcfBlob> = safeMalloc<HcfBlob>()
            let dataHb: HcfBlob = try {
                HcfBlob(data)
            } catch (e: Exception) {
                LibC.free(dataBlob)
                throw e
            }
            dataBlob.write(dataHb)
            let sigBlob: HcfBlob = try {
                HcfBlob(signatureData)
            } catch (e: Exception) {
                dataHb.free()
                LibC.free(dataBlob)
                throw e
            }
            var errCode: Int32 = 0
            let ret = FFiOHOSVerifyVerify(getID(), dataBlob, sigBlob, inout errCode)
            try {
                if (errCode != 0) {
                    callback(Some(BusinessException(errCode, "")), None)
                } else {
                    callback(None, ret)
                }
            } finally {
                dataHb.free()
                LibC.free(dataBlob)
                sigBlob.free()
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func verify(signatureData: DataBlob, callback: AsyncCallback<Bool>,
        data!: Option<DataBlob> = None): Unit {
        unsafe {
            let dataBlob: CPointer<HcfBlob> = match (data) {
                case Some(v) =>
                    let ptr = safeMalloc<HcfBlob>()
                    let blob = HcfBlob(v)
                    ptr.write(blob)
                    ptr
                case None => CPointer<HcfBlob>()
            }
            let sigBlob: HcfBlob = try {
                HcfBlob(signatureData)
            } catch (e: Exception) {
                if (dataBlob.isNotNull()) {
                    dataBlob.read().free()
                    LibC.free(dataBlob)
                }
                throw e
            }
            var errCode: Int32 = 0
            let ret = FFiOHOSVerifyVerify(getID(), dataBlob, sigBlob, inout errCode)
            try {
                if (errCode != 0) {
                    callback(Some(BusinessException(errCode, "")), None)
                } else {
                    callback(None, ret)
                }
            } finally {
                if (dataBlob.isNotNull()) {
                    dataBlob.read().free()
                    LibC.free(dataBlob)
                }
                sigBlob.free()
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func recover(signatureData: DataBlob, callback: AsyncCallback<?DataBlob>): Unit {
        unsafe {
            let input: HcfBlob = HcfBlob(signatureData)
            var output: HcfBlob = HcfBlob(CPointer<UInt8>(), 0)
            let errCode = FFiOHOSVerifyRecover(getID(), input, inout output)
            try {
                if (errCode != 0) {
                    callback(Some(BusinessException(errCode, "")), None)
                } else {
                    if (output.size == 0) {
                        callback(None, None)
                    } else {
                        let blob: DataBlob = output.toDataBlob()
                        callback(None, blob)
                    }
                }
            } finally {
                input.free()
                output.free()
            }
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func setVerifySpec(_itemType: SignSpecItem, itemValue: Int32): Unit {
        unsafe {
            let errCode = FFiOHOSVerifySetVerifySpecByNum(getID(), itemValue)
            checkAndThrow(errCode)
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func setVerifySpec(_itemType: SignSpecItem, itemValue: Array<UInt8>): Unit {
        unsafe {
            let blob = HcfBlob(DataBlob(itemValue))
            let errCode = FFiOHOSVerifySetVerifySpecByArr(getID(), blob)
            blob.free()
            checkAndThrow(errCode)
        }
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func getVerifySpec(itemType: SignSpecItem): ResultSpec {
        unsafe {
            match (itemType) {
                case PssMdNameStr | PssMgfNameStr | PssMgf1MdStr =>
                    var errCode: Int32 = 0
                    let returnString = FFiOHOSVerifyGetVerifySpecString(getID(), itemType.value, inout errCode)
                    checkAndThrow(errCode)
                    let res = ResultSpec.StringValue(returnString.toString())
                    LibC.free(returnString)
                    return res
                case PssSaltLenNum | PssTrailerFieldNum =>
                    var returnInt: Int32 = 0
                    let errCode = FFiOHOSVerifyGetVerifySpecNum(getID(), itemType.value, inout returnInt)
                    checkAndThrow(errCode)
                    return ResultSpec.Int32Value(returnInt)
                case _ => throw BusinessException(ERR_PARAMETER_ERROR, "specItem not support.")
            }
        }
    }
}
