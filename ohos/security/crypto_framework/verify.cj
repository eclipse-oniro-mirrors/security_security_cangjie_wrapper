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
 *
 * @param { String } algName - Signature verification algorithm to use. Currently, RSA, ECC, DSA, SM2, Ed25519 and
 *     ML-DSA are supported.
 *     If RSA PKCS1 is used, you must set the digest. If RSA PSS is used, you must set the digest and mask digest.
 *     When the RSA algorithm is used for signature verification, you can use recover to verify and recover the
 *     signed data.
 * @returns { Verify } Returns the Verify instance corresponding to the specified algorithm.
 * @throws { BusinessException } 801 - This operation is not supported.
 * @throws { BusinessException } 17620001 - Memory operation failed.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Signature",
    throwexception: true
]
public func createVerify(algName: String): Verify {
    return Verify(VerifyImpl(algName))
}

/**
 * Signature verification class, defining methods for verifying signatures using a public key.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Signature"
]
public class Verify {
    private let impl: VerifyImpl

    init(impl: VerifyImpl) {
        this.impl = impl
    }

    /**
     * Indicates the algorithm name of the Verify instance.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    public prop algName: String {
        get() {
            return impl.algName
        }
    }

    /**
     * Initializes the Verify object using a public key. This API uses an asynchronous callback to return the result.
     * init, update, and verify must be used together. init and verify are mandatory, and update is optional.
     *
     * @param { PubKey } pubKey - Public key used to initialize the Verify instance.
     * @param { AsyncCallback<Unit> } callback - Callback used to return the result.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17620002 - Failed to obtain the native object or convert parameters.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620003 - Parameter check failed. Possible causes: 1. Incorrect key type.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func initialize(pubKey: PubKey, callback: AsyncCallback<Unit>): Unit {
        spawn {
            try {
                unsafe {
                    let errCode = FFiOHOSVerifyInit(impl.getId(), pubKey.getId())
                    checkAndThrow(errCode)
                    callback(None, ())
                }
            } catch (err: BusinessException) {
                callback(err, None)
            }
        }
    }

    /**
     * Updates the data for signature verification. This API uses an asynchronous callback to return the result.
     *
     * This API can be called only after the Verify instance is initialized using init or initSync.
     *
     * Note:
     * You can call update multiple times or do not use update (call verify after init), depending on the data volume.
     *
     * The amount of the data to be passed in by update() (one-time or accumulative) is not limited. If there is a
     * large amount of data, you are advised to call update() multiple times to pass in the data by segment. This
     * prevents too much memory from being requested at a time.
     *
     * OnlyVerify cannot be used with update(). If OnlyVerify is specified, use verify() to pass in data.
     *
     * If the DSA algorithm is used for signature verification and the digest algorithm is NoHash, update() is not
     * supported. If update() is called in this case, ERR_CRYPTO_OPERATION will be returned.
     *
     * @param { DataBlob } data - Data to pass in.
     * @param { AsyncCallback<Unit> } callback - Callback used to return the result.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17620002 - Failed to obtain the native object or convert parameters.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620004 - Invalid function call.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func update(data: DataBlob, callback: AsyncCallback<Unit>): Unit {
        spawn {
            try {
                unsafe {
                    let blob = HcfBlob(data)
                    let errCode = FFiOHOSVerifyUpdate(impl.getId(), blob)
                    blob.free()
                    checkAndThrow(errCode)
                    callback(None, ())
                }
            } catch (err: BusinessException) {
                callback(err, None)
            }
        }
    }

    /**
     * Verifies the message, including the update data. This API uses an asynchronous callback to return the result.
     *
     * @param { DataBlob } data - Data to be verified.
     * @param { DataBlob } signatureData - The signature data.
     * @param { AsyncCallback<Bool> } callback - Callback used to return the result. The value **true**
     *     indicates that the signature verification is successful, and **false** indicates the opposite.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17620002 - Failed to obtain the native object or convert parameters.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620003 - Parameter check failed.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func verify(data: DataBlob, signatureData: DataBlob, callback: AsyncCallback<Bool>): Unit {
        spawn {
            var dataBlob: CPointer<HcfBlob> = CPointer<HcfBlob>()
            var dataHb: HcfBlob = HcfBlob(CPointer<UInt8>(), 0)
            var sigBlob: HcfBlob = HcfBlob(CPointer<UInt8>(), 0)
            try {
                unsafe {
                    dataBlob = safeMalloc<HcfBlob>()
                    dataHb = HcfBlob(data)
                    dataBlob.write(dataHb)
                    sigBlob = HcfBlob(signatureData)
                    var errCode: Int32 = 0
                    let ret = FFiOHOSVerifyVerify(impl.getId(), dataBlob, sigBlob, inout errCode)
                    checkAndThrow(errCode)
                    callback(None, ret)
                }
            } catch (err: BusinessException) {
                callback(err, None)
            } finally {
                unsafe {
                    dataHb.free()
                    LibC.free(dataBlob)
                    sigBlob.free()
                }
            }
        }
    }

    /**
     * Verifies the signature of the data. This API uses an asynchronous callback to return the result.
     *
     * @param { DataBlob } signatureData - Signature data.
     * @param { AsyncCallback<Bool> } callback - Callback used to return the result. The value **true**
     *     indicates that the signature verification is successful, and **false** indicates the opposite.
     * @param { ?DataBlob } [data] - Data to pass in.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17620002 - Failed to obtain the native object or convert parameters.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620003 - Parameter check failed.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func verify(signatureData: DataBlob, callback: AsyncCallback<Bool>,
        data!: Option<DataBlob> = None): Unit {
        spawn {
            var dataBlob: CPointer<HcfBlob> = CPointer<HcfBlob>()
            var sigBlob: HcfBlob = HcfBlob(CPointer<UInt8>(), 0)
            try {
                unsafe {
                    dataBlob = toBlobPtr(data)
                    sigBlob = HcfBlob(signatureData)
                    var errCode: Int32 = 0
                    let ret = FFiOHOSVerifyVerify(impl.getId(), dataBlob, sigBlob, inout errCode)
                    checkAndThrow(errCode)
                    callback(None, ret)
                }
            } catch (err: BusinessException) {
                callback(err, None)
            } finally {
                unsafe {
                    freeBlobPtr(dataBlob)
                    sigBlob.free()
                }
            }
        }
    }

    /**
     * Recovers the original data from a signature. This API uses an asynchronous callback to return the result.
     *
     * Note:
     * Currently, only RSA is supported.
     *
     * @param { DataBlob } signatureData - Signature data.
     * @param { AsyncCallback<?DataBlob> } callback - Callback used to return the result. If the operation is
     *     successful, **data** is the recovered original data.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17620002 - Failed to obtain the native object or convert parameters.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620004 - Invalid function call.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func recover(signatureData: DataBlob, callback: AsyncCallback<?DataBlob>): Unit {
        spawn {
            var input: HcfBlob = HcfBlob(CPointer<UInt8>(), 0)
            var output: HcfBlob = HcfBlob(CPointer<UInt8>(), 0)
            try {
                unsafe {
                    input = HcfBlob(signatureData)
                    let errCode = FFiOHOSVerifyRecover(impl.getId(), input, inout output)
                    checkAndThrow(errCode)
                }
                if (output.size == 0) {
                    callback(None, None)
                } else {
                    let blob: DataBlob = output.toDataBlob()
                    callback(None, blob)
                }
            } catch (err: BusinessException) {
                callback(err, None)
            } finally {
                unsafe {
                    input.free()
                    output.free()
                }
            }
        }
    }

    /**
     * Sets signature verification specifications. You can use this API to set signature verification parameters that
     * cannot be set by createVerify.
     *
     * Currently, only RSA and SM2 are supported.
     *
     * The parameters for signature verification must be the same as those for signing.
     *
     * @param { SignSpecItem } itemType - Signature verification parameter to set.
     * @param { Int32 } itemValue - Value of the signature verification parameter to set.
     * @throws { BusinessException } 801 - This operation is not supported.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620003 - Parameter check failed.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func setVerifySpec(itemType: SignSpecItem, itemValue: Int32): Unit {
        match (itemType) {
            case PssSaltLenNum =>
                unsafe {
                    let errCode = FFiOHOSVerifySetVerifySpecByNum(impl.getId(), itemValue)
                    checkAndThrow(errCode)
                }
            case _ => throw BusinessException(ERR_PARAMETER_ERROR, "[Verify] setVerifySpec: specItem not support.")
        }
    }

    /**
     * Sets the specified parameter for the Verify instance.
     *
     * Currently, only PSS_SALT_LEN in RSA and USER_ID in SM2 are supported.
     *
     * The parameters for signature verification must be the same as those for signing.
     *
     * @param { SignSpecItem } itemType - Indicates the specified parameter type.
     * @param { Array<UInt8> } itemValue - The value of the specified parameter.
     * @throws { BusinessException } 801 - This operation is not supported.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17620002 - Failed to obtain the native object or convert parameters.
     * @throws { BusinessException } 17620003 - Parameter check failed.
     * @throws { BusinessException } 17620004 - Invalid function call.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature",
        throwexception: true
    ]
    public func setVerifySpec(itemType: SignSpecItem, itemValue: Array<UInt8>): Unit {
        match (itemType) {
            case Sm2UserIdUint8arr =>
                unsafe {
                    let blob = HcfBlob(DataBlob(itemValue))
                    let errCode = FFiOHOSVerifySetVerifySpecByArr(impl.getId(), blob)
                    blob.free()
                    checkAndThrow(errCode)
                }
            case _ => throw BusinessException(ERR_PARAMETER_ERROR, "[Verify] setVerifySpec: specItem not support.")
        }
    }

    /**
     * Obtains signature verification specifications. Currently, only RSA is supported.
     *
     * @param { SignSpecItem } itemType - Signature verification parameter to obtain.
     * @returns { ResultSpec } Returns the value of the parameter obtained.
     * @throws { BusinessException } 801 - This operation is not supported.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620003 - Parameter check failed.
     */
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
                    let returnString = FFiOHOSVerifyGetVerifySpecString(impl.getId(), itemType.value, inout errCode)
                    checkAndThrow(errCode)
                    let res = ResultSpec.StringValue(returnString.toString())
                    LibC.free(returnString)
                    return res
                case PssSaltLenNum | PssTrailerFieldNum =>
                    var returnInt: Int32 = 0
                    let errCode = FFiOHOSVerifyGetVerifySpecNum(impl.getId(), itemType.value, inout returnInt)
                    checkAndThrow(errCode)
                    return ResultSpec.Int32Value(returnInt)
                case _ => throw BusinessException(ERR_PARAMETER_ERROR, "specItem not support.")
            }
        }
    }

    private static func toBlobPtr(opt: Option<DataBlob>): CPointer<HcfBlob> {
        return unsafe {
            match (opt) {
                case Some(v) =>
                    let ptr = safeMalloc<HcfBlob>()
                    let blob = HcfBlob(v)
                    ptr.write(blob)
                    ptr
                case None => CPointer<HcfBlob>()
            }
        }
    }

    private static func freeBlobPtr(ptr: CPointer<HcfBlob>): Unit {
        unsafe {
            if (ptr.isNotNull()) {
                ptr.read().free()
                LibC.free(ptr)
            }
        }
    }
}

class VerifyImpl <: RemoteDataLite {
    let algName: String

    init(algName: String) {
        super(unsafe {
            let cstr = LibC.mallocCString(algName)
            var errCode: Int32 = 0
            let id = FFiOHOSVerifyConstructor(cstr, inout errCode)
            LibC.free(cstr)
            checkAndThrow(errCode)
            id
        })
        this.algName = algName
    }

    ~init() {
        releaseFFIData(myDataId)
    }

    func getId(): Int64 {
        getID()
    }
}
