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

import ohos.labels.APILevel
import std.math.numeric.BigInt

/**
 * Enum for signature verification parameters, which can be set by using setVerifySpec, and obtained by using
 * getVerifySpec.
 *
 * Currently, only RSA and SM2 are supported.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Signature"
]
public enum SignSpecItem {
    /**
     * Message digest algorithm used with the PSS padding mode in RSA.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssMdNameStr
    |
    /**
     * Mask generation algorithm used with the PSS padding mode in RSA. Currently, only MGF1 is supported.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssMgfNameStr
    |
    /**
     * Message digest algorithm for the MGF1 mask generation used with the PSS padding mode in RSA.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssMgf1MdStr
    |
    /**
     * Length of the salt in bytes used with the PSS padding mode in RSA.
     *
     * According to the FIPS 186-4 standard, sLen should be greater than or equal to 0 and less than or equal to the
     * hash length.
     *
     * Default values:
     * - For sign, automatically calculate the maximum salt length.
     * - For verify, automatically calculate the salt length.
     *
     * Special values:
     * - For sign, you can also set the value to -1 to use the digest length as the salt length, and -2 or -3 to
     * automatically calculate the maximum salt length. The recommended value is -1.
     * - For verify, you can also set the value to -1 to use the digest length as the salt length, -2 to automatically
     * calculate the salt length, or -3 to use the maximum salt length. The recommended value is -2.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssSaltLenNum
    |
    /**
     * Trailer field used in the encoding operation when PSS padding mode is used in RSA.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    PssTrailerFieldNum
    |
    /**
     * User ID field in SM2.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    Sm2UserIdUint8arr
    |
    /**
     * Indicates whether deterministic signing is used for the ML-DSA signing and verifying process.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    MlDsaDeterministicBool
    |
    /**
     * Indicates the mu parameter value for the ML-DSA signing and verifying process.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    MlDsaMuBool
    |
    /**
     * Indicates the context data for the ML-DSA signing and verifying process.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    MlDsaContextUint8arr
    | ...

    prop value: Int32 {
        get() {
            match (this) {
                case PssMdNameStr => 100
                case PssMgfNameStr => 101
                case PssMgf1MdStr => 102
                case PssSaltLenNum => 103
                case PssTrailerFieldNum => 104
                case Sm2UserIdUint8arr => 105
                case MlDsaDeterministicBool => 106
                case MlDsaMuBool => 107
                case MlDsaContextUint8arr => 108
                case _ => throw IllegalArgumentException("The type is not supported.")
            }
        }
    }
}

extend SignSpecItem <: ToString {
    /**
     * Converts the SignSpecItem to its string representation.
     * @returns { String } A string representation of the SignSpecItem.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    public func toString(): String {
        match (this) {
            case PssMdNameStr => "PssMdNameStr"
            case PssMgfNameStr => "PssMgfNameStr"
            case PssMgf1MdStr => "PssMgf1MdStr"
            case PssSaltLenNum => "PssSaltLenNum"
            case PssTrailerFieldNum => "PssTrailerFieldNum"
            case Sm2UserIdUint8arr => "Sm2UserIdUint8arr"
            case MlDsaDeterministicBool => "MlDsaDeterministicBool"
            case MlDsaMuBool => "MlDsaMuBool"
            case MlDsaContextUint8arr => "MlDsaContextUint8arr"
            case _ => throw IllegalArgumentException("The type is not supported.")
        }
    }
}

extend SignSpecItem <: Equatable<SignSpecItem> {
    /**
     * Compares this SignSpecItem with another for equality.
     * @param { SignSpecItem } other - The SignSpecItem to compare with.
     * @returns { Bool } True if both modes are equal, false otherwise.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    public operator func ==(other: SignSpecItem): Bool {
        return this.toString() == other.toString()
    }

    /**
     * Compares this SignSpecItem with another for inequality.
     * @param { SignSpecItem } other - The SignSpecItem to compare with.
     * @returns { Bool } True if both modes are not equal, false otherwise.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    public operator func !=(other: SignSpecItem): Bool {
        return this.toString() != other.toString()
    }
}

/**
 * Enumerates the asymmetric key parameters.
 */
@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
]
public enum AsyKeySpecItem {
    /**
     * Prime modulus **p** in the DSA algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaPBn
    |
    /**
     * Parameter **q**, prime factor of (p - 1) in the DSA algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaQBn
    |
    /**
     * Parameter **g** in the DSA algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaGBn
    |
    /**
     * Private key **sk** in the DSA algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaSkBn
    |
    /**
     * Public key **pk** in the DSA algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaPkBn
    |
    /**
     * Prime number **p** in the **Fp** field of the elliptic curve in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccFpPBn
    |
    /**
     * First coefficient **a** of the elliptic curve in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccABn
    |
    /**
     * Second coefficient **b** of the elliptic curve in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccBBn
    |
    /**
     * X coordinate of the base point **g** in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccGXBn
    |
    /**
     * Y coordinate of the base point **g** in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccGYBn
    |
    /**
     * Order **n** of the base point **g** in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccNBn
    |
    /**
     * Cofactor **h** in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccHNum
    |
    /**
     * Private key **sk** in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccSkBn
    |
    /**
     * X coordinate of the public key **pk** (a point on the elliptic curve) in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccPkXBn
    |
    /**
     * Y coordinate of the public key **pk** (a point on the elliptic curve) in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccPkYBn
    |
    /**
     * Elliptic curve field type in the ECC algorithm. Currently, only the **Fp** field is supported.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccFieldTypeStr
    |
    /**
     * Size of the field in the ECC algorithm, in bits.
     *
     * Note: The size of the **Fp** field is the length of the prime **p**, in bits.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccFieldSizeNum
    |
    /**
     * Standards for Efficient Cryptography Group (SECG) curve name in the ECC algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccCurveNameStr
    |
    /**
     * Modulus **n** in the RSA algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    RsaNBn
    |
    /**
     * Private key **sk** (private key exponent **d**) in the RSA algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    RsaSkBn
    |
    /**
     * Public key **pk** (public key exponent **e**) in the RSA algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    RsaPkBn
    |
    /**
     * Prime **p** in the DH algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhPBn
    |
    /**
     * Parameter **g** in the DH algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhGBn
    |
    /**
     * Length of the private key in the DH algorithm, in bits.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhLNum
    |
    /**
     * Private key **sk** in the DH algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhSkBn
    |
    /**
     * Public key **pk** in the DH algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhPkBn
    |
    /**
     * Private key **sk** in the Ed25519 algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    Ed25519SkBn
    |
    /**
     * Public key **pk** in the Ed25519 algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    Ed25519PkBn
    |
    /**
     * Private key **sk** in the X25519 algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    X25519SkBn
    |
    /**
     * Public key **pk** in the X25519 algorithm.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    X25519PkBn
    | ...

    prop value: Int32 {
        get() {
            match (this) {
                case DsaPBn => 101
                case DsaQBn => 102
                case DsaGBn => 103
                case DsaSkBn => 104
                case DsaPkBn => 105
                case EccFpPBn => 201
                case EccABn => 202
                case EccBBn => 203
                case EccGXBn => 204
                case EccGYBn => 205
                case EccNBn => 206
                case EccHNum => 207
                case EccSkBn => 208
                case EccPkXBn => 209
                case EccPkYBn => 210
                case EccFieldTypeStr => 211
                case EccFieldSizeNum => 212
                case EccCurveNameStr => 213
                case RsaNBn => 301
                case RsaSkBn => 302
                case RsaPkBn => 303
                case DhPBn => 401
                case DhGBn => 402
                case DhLNum => 403
                case DhSkBn => 404
                case DhPkBn => 405
                case Ed25519SkBn => 501
                case Ed25519PkBn => 502
                case X25519SkBn => 601
                case X25519PkBn => 602
                case _ => throw IllegalArgumentException("The type is not supported.")
            }
        }
    }
}

extend AsyKeySpecItem <: ToString {
    /**
     * Converts the AsyKeySpecItem to its string representation.
     * @returns { String } A string representation of the AsyKeySpecItem.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public func toString(): String {
        match (this) {
            case DsaPBn => "DsaPBn"
            case DsaQBn => "DsaQBn"
            case DsaGBn => "DsaGBn"
            case DsaSkBn => "DsaSkBn"
            case DsaPkBn => "DsaPkBn"
            case EccFpPBn => "EccFpPBn"
            case EccABn => "EccABn"
            case EccBBn => "EccBBn"
            case EccGXBn => "EccGXBn"
            case EccGYBn => "EccGYBn"
            case EccNBn => "EccNBn"
            case EccHNum => "EccHNum"
            case EccSkBn => "EccSkBn"
            case EccPkXBn => "EccPkXBn"
            case EccPkYBn => "EccPkYBn"
            case EccFieldTypeStr => "EccFieldTypeStr"
            case EccFieldSizeNum => "EccFieldSizeNum"
            case EccCurveNameStr => "EccCurveNameStr"
            case RsaNBn => "RsaNBn"
            case RsaSkBn => "RsaSkBn"
            case RsaPkBn => "RsaPkBn"
            case DhPBn => "DhPBn"
            case DhGBn => "DhGBn"
            case DhLNum => "DhLNum"
            case DhSkBn => "DhSkBn"
            case DhPkBn => "DhPkBn"
            case Ed25519SkBn => "Ed25519SkBn"
            case Ed25519PkBn => "Ed25519PkBn"
            case X25519SkBn => "X25519SkBn"
            case X25519PkBn => "X25519PkBn"
            case _ => throw IllegalArgumentException("The type is not supported.")
        }
    }
}

extend AsyKeySpecItem <: Equatable<AsyKeySpecItem> {
    /**
     * Compares this AsyKeySpecItem with another for equality.
     * @param { AsyKeySpecItem } other - The AsyKeySpecItem to compare with.
     * @returns { Bool } True if both modes are equal, false otherwise.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public operator func ==(other: AsyKeySpecItem): Bool {
        return this.toString() == other.toString()
    }

    /**
     * Compares this AsyKeySpecItem with another for inequality.
     * @param { AsyKeySpecItem } other - The AsyKeySpecItem to compare with.
     * @returns { Bool } True if both modes are not equal, false otherwise.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public operator func !=(other: AsyKeySpecItem): Bool {
        return this.toString() != other.toString()
    }
}

@!APILevel[
    since: "26.1.0",
    syscap: "SystemCapability.Security.CryptoFramework"
]
public enum ResultSpec {
    /**
     * Represents a BigInt value, corresponding to the ArkTS bigint type.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    BigintValue(BigInt)
    |
    /**
     * Represents an Int32 value, corresponding to the ArkTS int (number) type.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    Int32Value(Int32)
    |
    /**
     * Represents a String value, corresponding to the ArkTS string type.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    StringValue(String)
    |
    /**
     * Represents a UInt8Array value, corresponding to the ArkTS Uint8Array type.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    Uint8ArrayValue(Array<UInt8>)
    | ...
}

extend ResultSpec <: ToString {
    /**
     * Converts the ResultSpec to its string representation.
     * @returns { String } A string representation of the ResultSpec.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public func toString(): String {
        match (this) {
            case BigintValue(v) => v.toString()
            case Int32Value(v) => v.toString()
            case StringValue(v) => v
            case Uint8ArrayValue(v) => v.toString()
            case _ => throw IllegalArgumentException("The type is not supported.")
        }
    }
}

extend ResultSpec <: Equatable<ResultSpec> {
    /**
     * Compares this ResultSpec with another for equality.
     * @param { ResultSpec } other - The ResultSpec to compare with.
     * @returns { Bool } True if both values are equal, false otherwise.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public operator func ==(other: ResultSpec): Bool {
        return this.toString() == other.toString()
    }

    /**
     * Compares this ResultSpec with another for inequality.
     * @param { ResultSpec } other - The ResultSpec to compare with.
     * @returns { Bool } True if both values are not equal, false otherwise.
     */
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public operator func !=(other: ResultSpec): Bool {
        return this.toString() != other.toString()
    }
}
