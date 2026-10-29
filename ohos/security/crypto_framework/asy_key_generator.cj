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
}

/**
 * Creates an AsyKeyGenerator instance based on the specified algorithm.
 *
 * @param { String } algName - Algorithm used by the asymmetric keys. For details, see the Asymmetric Key Generation
 *     and Conversion Specifications.
 * @returns { AsyKeyGenerator } Returns the AsyKeyGenerator instance corresponding to the specified algorithm.
 * @throws { BusinessException } 801 - This operation is not supported.
 * @throws { BusinessException } 17620001 - Memory operation failed.
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

    /**
     * Indicates the algorithm name of the AsyKeyGenerator object.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public prop algName: String {
        get() {
            return _algName
        }
    }

    /**
     * Generates a random key pair using this asymmetric key generator. This API uses an asynchronous callback to
     * return the result.
     *
     * @param { AsyncCallback<KeyPair> } callback - Callback used to return the result. If the operation is
     *     successful, **data** is the key pair obtained.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func generateKeyPair(callback: AsyncCallback<KeyPair>): Unit {
        spawn {
            try {
                unsafe {
                    var errCode: Int32 = 0
                    let id = FFiOHOSAsyKeyGeneratorGenerateKeyPair(getID(), inout errCode)
                    checkAndThrow(errCode)
                    let keyPair = KeyPair(id, _algName)
                    callback(None, keyPair)
                }
            } catch (err: BusinessException) {
                callback(err, None)
            }
        }
    }

    /**
     * Converts data into an asymmetric key pair. This API uses an asynchronous callback to return the result.
     *
     * @param { AsyncCallback<KeyPair> } callback - Callback used to return the result. If the operation is
     *     successful, **data** is the key pair obtained.
     * @param { ?DataBlob } [pubKey] - Public key material to convert. If no public key needs to be converted, set this
     *     parameter to **None**.
     * @param { ?DataBlob } [priKey] - Private key material to convert. If no private key needs to be converted, set
     *     this parameter to **None**.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620003 - Parameter check failed.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertKey(callback: AsyncCallback<KeyPair>, pubKey!: Option<DataBlob> = None,
        priKey!: Option<DataBlob> = None): Unit {
        spawn {
            var pub: CPointer<HcfBlob> = CPointer<HcfBlob>()
            var pri: CPointer<HcfBlob> = CPointer<HcfBlob>()
            try {
                unsafe {
                    pub = match (pubKey) {
                        case Some(v) =>
                            let ptr = safeMalloc<HcfBlob>()
                            let blob = HcfBlob(v)
                            ptr.write(blob)
                            ptr
                        case None => CPointer<HcfBlob>()
                    }
                    pri = try {
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
                    checkAndThrow(errCode)
                    let keyPair = KeyPair(id, _algName)
                    callback(None, keyPair)
                }
            } catch (err: BusinessException) {
                callback(err, None)
            } finally {
                unsafe {
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
    }

    /**
     * Converts data into an asymmetric key pair. This API uses an asynchronous callback to return the result.
     *
     * Note:
     * 1. When convertPemKey() is used to convert an external string into an asymmetric key object defined by the
     * Crypto framework, the public key must comply with the ASN.1 syntax, X.509 specifications, and PEM encoding
     * format, and the private key must comply with the ASN.1 syntax, PKCS #8 specifications, and PEM encoding format.
     * 2. In convertPemKey(), you can pass in either pubKey or priKey, or both of them. If one of them is passed in,
     * the returned KeyPair instance contains only the key converted from the data you passed in.
     * 3. When convertPemKey is used to convert an external string into an asymmetric key object defined by the Crypto
     * framework, the system does not verify whether the specifications of the generated key object are the same as
     * the key specifications specified for the asymmetric key generator.
     *
     * @param { AsyncCallback<KeyPair> } callback - Callback used to return the result. If the operation is
     *     successful, **data** is the key pair obtained.
     * @param { ?String } [pubKey] - Public key material to convert. If no public key needs to be converted, set
     *     this parameter to **None**.
     * @param { ?String } [priKey] - Private key material to convert. If no private key needs to be converted,
     *     set this parameter to **None**. Note: The public key and private key materials cannot be both None or empty
     *     strings.
     * @throws { BusinessException } 17620001 - Memory operation failed.
     * @throws { BusinessException } 17630001 - Crypto operation error.
     * @throws { BusinessException } 17620003 - Parameter check failed.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey",
        throwexception: true
    ]
    public func convertPemKey(callback: AsyncCallback<KeyPair>, pubKey!: Option<String> = None,
        priKey!: Option<String> = None): Unit {
        spawn {
            var pubCStr: CString = CString(CPointer<UInt8>())
            var priCStr: CString = CString(CPointer<UInt8>())
            try {
                unsafe {
                    pubCStr = match (pubKey) {
                        case Some(v) => LibC.mallocCString(v)
                        case None => CString(CPointer<UInt8>())
                    }
                    priCStr = try {
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
                    checkAndThrow(errCode)
                    let keyPair = KeyPair(id, _algName)
                    callback(None, keyPair)
                }
            } catch (err: BusinessException) {
                callback(err, None)
            } finally {
                unsafe {
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
    }
}
