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
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Signature"
    ]
    public operator func ==(other: SignSpecItem): Bool {
        return this.toString() == other.toString()
    }

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
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaGBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaSkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DsaPkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccFpPBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccABn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccBBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccGXBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccGYBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccNBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccHNum
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccSkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccPkXBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccPkYBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccFieldTypeStr
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccFieldSizeNum
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    EccCurveNameStr
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    RsaNBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    RsaSkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    RsaPkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhPBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhGBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhLNum
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhSkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    DhPkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    Ed25519SkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    Ed25519PkBn
    |
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    X25519SkBn
    |
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
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework.Key.AsymKey"
    ]
    public operator func ==(other: AsyKeySpecItem): Bool {
        return this.toString() == other.toString()
    }

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
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    BigintValue(BigInt)
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

extend ResultSpec <: ToString {
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
    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public operator func ==(other: ResultSpec): Bool {
        return this.toString() == other.toString()
    }

    @!APILevel[
        since: "26.1.0",
        syscap: "SystemCapability.Security.CryptoFramework"
    ]
    public operator func !=(other: ResultSpec): Bool {
        return this.toString() != other.toString()
    }
}
