/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.fido2.util;

import java.util.Optional;

public final class Either<L, R> {

    private final boolean isRight;
    private final L leftValue;
    private final R rightValue;

    private Either(R rightValue) {
        this.isRight = true;
        this.leftValue = null;
        this.rightValue = rightValue;
    }

    private Either(boolean dummy, L leftValue) {
        this.isRight = false;
        this.leftValue = leftValue;
        this.rightValue = null;
    }

    public final boolean isLeft() {
        return !isRight();
    }

    public final boolean isRight() {
        return isRight;
    }

    public final Optional<L> left() {
        if (isLeft()) {
            return Optional.of(leftValue);
        } else {
            throw new IllegalStateException("Cannot call left() on a right value.");
        }
    }

    public final Optional<R> right() {
        if (isRight()) {
            return Optional.of(rightValue);
        } else {
            throw new IllegalStateException("Cannot call right() on a left value.");
        }
    }

    public static <L, R> Either<L, R> left(L value) {
        return new Either<>(false, value);
    }

    public static <L, R> Either<L, R> right(R value) {
        return new Either<>(value);
    }

}
