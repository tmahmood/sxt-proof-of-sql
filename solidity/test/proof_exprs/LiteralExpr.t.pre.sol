// SPDX-License-Identifier: UNLICENSED
// This is licensed under the Cryptographic Open Software License 1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import "../../src/base/Constants.sol";
import "../../src/base/Errors.sol";
import {LiteralExpr} from "../../src/proof_exprs/LiteralExpr.pre.sol";
import {F} from "../base/FieldUtil.sol";

contract LiteralExprTest is Test {
    function testLiteralExpr() public pure {
        bytes memory exprIn = abi.encodePacked(DATA_TYPE_BIGINT_VARIANT, int64(2), hex"abcdef");
        bytes memory expectedExprOut = hex"abcdef";
        (bytes memory exprOut, uint256 eval) = LiteralExpr.__literalExprEvaluate(exprIn, 3);
        assert(eval == 6);
        assert(exprOut.length == expectedExprOut.length);
        uint256 exprOutLength = exprOut.length;
        for (uint256 i = 0; i < exprOutLength; ++i) {
            assert(exprOut[i] == expectedExprOut[i]);
        }
    }

    function testFuzzBigIntLiteralExpr(int64 literalValue, uint256 chiInEval, bytes memory trailingExpr) public pure {
        bytes memory exprIn = abi.encodePacked(DATA_TYPE_BIGINT_VARIANT, literalValue, trailingExpr);
        (bytes memory exprOut, uint256 eval) = LiteralExpr.__literalExprEvaluate(exprIn, chiInEval);
        assert(eval == (F.from(literalValue) * F.from(chiInEval)).into());
        assert(exprOut.length == trailingExpr.length);
        uint256 exprOutLength = exprOut.length;
        for (uint256 i = 0; i < exprOutLength; ++i) {
            assert(exprOut[i] == trailingExpr[i]);
        }
    }

    function testFuzzInvalidLiteralVariant(uint32 variant) public {
        vm.assume(variant > DATA_TYPE_TIMESTAMP_VARIANT);
        bytes memory exprIn = abi.encodePacked(variant, int64(2), hex"abcdef");
        vm.expectRevert(Errors.UnsupportedDataTypeVariant.selector);
        LiteralExpr.__literalExprEvaluate(exprIn, 3);
    }
}
