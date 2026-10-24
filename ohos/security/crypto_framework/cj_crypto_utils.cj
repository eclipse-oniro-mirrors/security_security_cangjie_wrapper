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

import std.collection.HashMap
import ohos.business_exception.{BusinessException, ERR_PARAMETER_ERROR}

const SPEC_ITEM_TYPE_BIG_INT = 1i32
const SPEC_ITEM_TYPE_NUM = 2i32
const SPEC_ITEM_TYPE_STR = 3i32

let ASY_KEY_SPEC_RELATION_MAP = HashMap<Int32, Int32>(
    [
        (DsaPBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (DsaQBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (DsaGBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (DsaSkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (DsaPkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccFpPBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccABn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccBBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccGXBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccGYBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccNBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccHNum.value, SPEC_ITEM_TYPE_NUM),
        (EccSkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccPkXBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccPkYBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (EccFieldTypeStr.value, SPEC_ITEM_TYPE_STR),
        (EccFieldSizeNum.value, SPEC_ITEM_TYPE_NUM),
        (EccCurveNameStr.value, SPEC_ITEM_TYPE_STR),
        (RsaNBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (RsaSkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (RsaPkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (DhPBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (DhGBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (DhLNum.value, SPEC_ITEM_TYPE_NUM),
        (DhSkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (DhPkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (Ed25519SkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (Ed25519PkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (X25519SkBn.value, SPEC_ITEM_TYPE_BIG_INT),
        (X25519PkBn.value, SPEC_ITEM_TYPE_BIG_INT)
    ]
)

func getAsyKeySpecType(targetItemType: Int32): Int32 {
    return ASY_KEY_SPEC_RELATION_MAP.get(targetItemType) ?? throw BusinessException(ERR_PARAMETER_ERROR,
        "AsyKeySpecItem not support!")
}
