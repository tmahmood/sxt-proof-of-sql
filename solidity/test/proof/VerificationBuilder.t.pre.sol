// SPDX-License-Identifier: UNLICENSED
// This is licensed under the Cryptographic Open Software License 1.0
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import "../../src/base/Constants.sol";
import {Errors} from "../../src/base/Errors.sol";
import {VerificationBuilder} from "../../src/proof/VerificationBuilder.pre.sol";

contract VerificationBuilderTest is Test {
    function testBuilderNewAllocatesValidMemory(bytes memory) public pure {
        uint256 startFreePtr;
        uint256 endFreePtr;
        uint256 builderPtr;
        assembly {
            startFreePtr := mload(FREE_PTR)
        }
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        assembly {
            endFreePtr := mload(FREE_PTR)
            builderPtr := builder
        }
        // NOTE: because solidity allocates more memory than it needs, we end up with a gap between the
        // end of the builder and the beginning of any new memory allocated.
        // This is why we this is an inequality instead of an equality.
        // This is also why we have the `testYulBuilderNewAllocatesValidMemory` check.
        assert(builderPtr >= startFreePtr); // solhint-disable-line gas-strict-inequalities
        assert(endFreePtr - builderPtr == VERIFICATION_BUILDER_SIZE);
    }

    function testYulBuilderNew(bytes memory) public pure {
        uint256 startFreePtr;
        uint256 endFreePtr;
        uint256 builderPtr;
        assembly {
            /// IMPORT-YUL ../../src/proof/VerificationBuilder.pre.sol
            function builder_new() -> builder {
                revert(0, 0)
            }
            startFreePtr := mload(FREE_PTR)
            builderPtr := builder_new()
            endFreePtr := mload(FREE_PTR)
        }
        assert(builderPtr == startFreePtr);
        assert(endFreePtr - builderPtr == VERIFICATION_BUILDER_SIZE);
    }

    function testSetZeroChallenges() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory challenges = new uint256[](0);
        VerificationBuilder.__setChallenges(builder, challenges);
        assert(builder.challenges.length == 0);
    }

    function testSetChallenges() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory challenges = new uint256[](3);
        challenges[0] = 0x12345678;
        challenges[1] = 0x23456789;
        challenges[2] = 0x3456789A;
        VerificationBuilder.__setChallenges(builder, challenges);
        assert(builder.challenges.length == 3);
        assert(builder.challenges[0] == 0x12345678);
        assert(builder.challenges[1] == 0x23456789);
        assert(builder.challenges[2] == 0x3456789A);
    }

    function testFuzzSetChallenges(uint256[] memory values) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setChallenges(builder, values);
        assert(builder.challenges.length == values.length);
        uint256 valuesLength = values.length;
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(builder.challenges[i] == values[i]);
        }
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeZeroChallenges() public {
        VerificationBuilder.Builder memory builder;
        builder.challenges = new uint256[](0);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeChallenge(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeChallenges() public {
        VerificationBuilder.Builder memory builder;
        builder.challenges = new uint256[](3);
        builder.challenges[0] = 0x12345678;
        builder.challenges[1] = 0x23456789;
        builder.challenges[2] = 0x3456789A;
        assert(VerificationBuilder.__consumeChallenge(builder) == 0x12345678);
        assert(VerificationBuilder.__consumeChallenge(builder) == 0x23456789);
        assert(VerificationBuilder.__consumeChallenge(builder) == 0x3456789A);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeChallenge(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testFuzzConsumeChallenges(uint256[] memory values) public {
        VerificationBuilder.Builder memory builder;
        uint256 valuesLength = values.length;
        builder.challenges = new uint256[](valuesLength);
        for (uint256 i = 0; i < valuesLength; ++i) {
            builder.challenges[i] = values[i];
        }
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(VerificationBuilder.__consumeChallenge(builder) == values[i]);
        }
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeChallenge(builder);
    }

    function testSetZeroFirstRoundMLEs() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](0);
        VerificationBuilder.__setFirstRoundMLEs(builder, values);
        assert(builder.firstRoundMLEs.length == 0);
    }

    function testSetFirstRoundMLEs() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](3);
        values[0] = 0x12345678;
        values[1] = 0x23456789;
        values[2] = 0x3456789A;
        VerificationBuilder.__setFirstRoundMLEs(builder, values);
        assert(builder.firstRoundMLEs.length == 3);
        assert(builder.firstRoundMLEs[0] == 0x12345678);
        assert(builder.firstRoundMLEs[1] == 0x23456789);
        assert(builder.firstRoundMLEs[2] == 0x3456789A);
    }

    function testFuzzSetFirstRoundMLEs(uint256[] memory values) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setFirstRoundMLEs(builder, values);
        assert(builder.firstRoundMLEs.length == values.length);
        uint256 valuesLength = values.length;
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(builder.firstRoundMLEs[i] == values[i]);
        }
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeZeroFirstRoundMLEs() public {
        VerificationBuilder.Builder memory builder;
        builder.firstRoundMLEs = new uint256[](0);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeFirstRoundMLE(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeFirstRoundMLEs() public {
        VerificationBuilder.Builder memory builder;
        builder.firstRoundMLEs = new uint256[](3);
        builder.firstRoundMLEs[0] = 0x12345678;
        builder.firstRoundMLEs[1] = 0x23456789;
        builder.firstRoundMLEs[2] = 0x3456789A;
        assert(VerificationBuilder.__consumeFirstRoundMLE(builder) == 0x12345678);
        assert(VerificationBuilder.__consumeFirstRoundMLE(builder) == 0x23456789);
        assert(VerificationBuilder.__consumeFirstRoundMLE(builder) == 0x3456789A);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeFirstRoundMLE(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testFuzzConsumeFirstRoundMLEs(uint256[] memory values) public {
        VerificationBuilder.Builder memory builder;
        uint256 valuesLength = values.length;
        builder.firstRoundMLEs = new uint256[](valuesLength);
        for (uint256 i = 0; i < valuesLength; ++i) {
            builder.firstRoundMLEs[i] = values[i];
        }
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(VerificationBuilder.__consumeFirstRoundMLE(builder) == values[i]);
        }
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeFirstRoundMLE(builder);
    }

    function testSetZeroFinalRoundMLEs() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](0);
        VerificationBuilder.__setFinalRoundMLEs(builder, values);
        assert(builder.finalRoundMLEs.length == 0);
    }

    function testSetFinalRoundMLEs() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](3);
        values[0] = 0x12345678;
        values[1] = 0x23456789;
        values[2] = 0x3456789A;
        VerificationBuilder.__setFinalRoundMLEs(builder, values);
        assert(builder.finalRoundMLEs.length == 3);
        assert(builder.finalRoundMLEs[0] == 0x12345678);
        assert(builder.finalRoundMLEs[1] == 0x23456789);
        assert(builder.finalRoundMLEs[2] == 0x3456789A);
    }

    function testFuzzSetFinalRoundMLEs(uint256[] memory values) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setFinalRoundMLEs(builder, values);
        assert(builder.finalRoundMLEs.length == values.length);
        uint256 valuesLength = values.length;
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(builder.finalRoundMLEs[i] == values[i]);
        }
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeZeroFinalRoundMLEs() public {
        VerificationBuilder.Builder memory builder;
        builder.finalRoundMLEs = new uint256[](0);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeFinalRoundMLE(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeFinalRoundMLEs() public {
        VerificationBuilder.Builder memory builder;
        builder.finalRoundMLEs = new uint256[](3);
        builder.finalRoundMLEs[0] = 0x12345678;
        builder.finalRoundMLEs[1] = 0x23456789;
        builder.finalRoundMLEs[2] = 0x3456789A;
        assert(VerificationBuilder.__consumeFinalRoundMLE(builder) == 0x12345678);
        assert(VerificationBuilder.__consumeFinalRoundMLE(builder) == 0x23456789);
        assert(VerificationBuilder.__consumeFinalRoundMLE(builder) == 0x3456789A);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeFinalRoundMLE(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testFuzzConsumeFinalRoundMLEs(uint256[] memory values) public {
        VerificationBuilder.Builder memory builder;
        uint256 valuesLength = values.length;
        builder.finalRoundMLEs = new uint256[](valuesLength);
        for (uint256 i = 0; i < valuesLength; ++i) {
            builder.finalRoundMLEs[i] = values[i];
        }
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(VerificationBuilder.__consumeFinalRoundMLE(builder) == values[i]);
        }
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeFinalRoundMLE(builder);
    }

    function testSetZeroChiEvaluations() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](0);
        VerificationBuilder.__setChiEvaluations(builder, values);
        assert(builder.chiEvaluations.length == 0);
    }

    function testSetChiEvaluations() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](3);
        values[0] = 0x12345678;
        values[1] = 0x23456789;
        values[2] = 0x3456789A;
        VerificationBuilder.__setChiEvaluations(builder, values);
        assert(builder.chiEvaluations.length == 3);
        assert(builder.chiEvaluations[0] == 0x12345678);
        assert(builder.chiEvaluations[1] == 0x23456789);
        assert(builder.chiEvaluations[2] == 0x3456789A);
    }

    function testFuzzSetChiEvaluations(uint256[] memory values) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setChiEvaluations(builder, values);
        assert(builder.chiEvaluations.length == values.length);
        uint256 valuesLength = values.length;
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(builder.chiEvaluations[i] == values[i]);
        }
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeZeroChiEvaluations() public {
        VerificationBuilder.Builder memory builder;
        builder.chiEvaluations = new uint256[](0);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeChiEvaluation(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeChiEvaluations() public {
        VerificationBuilder.Builder memory builder;
        builder.chiEvaluations = new uint256[](3);
        builder.chiEvaluations[0] = 0x12345678;
        builder.chiEvaluations[1] = 0x23456789;
        builder.chiEvaluations[2] = 0x3456789A;
        assert(VerificationBuilder.__consumeChiEvaluation(builder) == 0x12345678);
        assert(VerificationBuilder.__consumeChiEvaluation(builder) == 0x23456789);
        assert(VerificationBuilder.__consumeChiEvaluation(builder) == 0x3456789A);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeChiEvaluation(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testFuzzConsumeChiEvaluations(uint256[] memory values) public {
        VerificationBuilder.Builder memory builder;
        uint256 valuesLength = values.length;
        builder.chiEvaluations = new uint256[](valuesLength);
        for (uint256 i = 0; i < valuesLength; ++i) {
            builder.chiEvaluations[i] = values[i];
        }
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(VerificationBuilder.__consumeChiEvaluation(builder) == values[i]);
        }
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeChiEvaluation(builder);
    }

    function testSetZeroRhoEvaluations() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](0);
        VerificationBuilder.__setRhoEvaluations(builder, values);
        assert(builder.rhoEvaluations.length == 0);
    }

    function testSetRhoEvaluations() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](3);
        values[0] = 0x12345678;
        values[1] = 0x23456789;
        values[2] = 0x3456789A;
        VerificationBuilder.__setRhoEvaluations(builder, values);
        assert(builder.rhoEvaluations.length == 3);
        assert(builder.rhoEvaluations[0] == 0x12345678);
        assert(builder.rhoEvaluations[1] == 0x23456789);
        assert(builder.rhoEvaluations[2] == 0x3456789A);
    }

    function testFuzzSetRhoEvaluations(uint256[] memory values) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setRhoEvaluations(builder, values);
        assert(builder.rhoEvaluations.length == values.length);
        uint256 valuesLength = values.length;
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(builder.rhoEvaluations[i] == values[i]);
        }
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeZeroRhoEvaluations() public {
        VerificationBuilder.Builder memory builder;
        builder.rhoEvaluations = new uint256[](0);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeRhoEvaluation(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testConsumeRhoEvaluations() public {
        VerificationBuilder.Builder memory builder;
        builder.rhoEvaluations = new uint256[](3);
        builder.rhoEvaluations[0] = 0x12345678;
        builder.rhoEvaluations[1] = 0x23456789;
        builder.rhoEvaluations[2] = 0x3456789A;
        assert(VerificationBuilder.__consumeRhoEvaluation(builder) == 0x12345678);
        assert(VerificationBuilder.__consumeRhoEvaluation(builder) == 0x23456789);
        assert(VerificationBuilder.__consumeRhoEvaluation(builder) == 0x3456789A);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeRhoEvaluation(builder);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testFuzzConsumeRhoEvaluations(uint256[] memory values) public {
        VerificationBuilder.Builder memory builder;
        uint256 valuesLength = values.length;
        builder.rhoEvaluations = new uint256[](valuesLength);
        for (uint256 i = 0; i < valuesLength; ++i) {
            builder.rhoEvaluations[i] = values[i];
        }
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(VerificationBuilder.__consumeRhoEvaluation(builder) == values[i]);
        }
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__consumeRhoEvaluation(builder);
    }

    function testSetZeroConstraintMultipliers() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](0);
        VerificationBuilder.__setConstraintMultipliers(builder, values);
        assert(builder.constraintMultipliers.length == 0);
    }

    function testSetConstraintMultipliers() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory values = new uint256[](3);
        values[0] = 0x12345678;
        values[1] = 0x23456789;
        values[2] = 0x3456789A;
        VerificationBuilder.__setConstraintMultipliers(builder, values);
        assert(builder.constraintMultipliers.length == 3);
        assert(builder.constraintMultipliers[0] == 0x12345678);
        assert(builder.constraintMultipliers[1] == 0x23456789);
        assert(builder.constraintMultipliers[2] == 0x3456789A);
    }

    function testFuzzSetConstraintMultipliers(uint256[] memory values) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setConstraintMultipliers(builder, values);
        assert(builder.constraintMultipliers.length == values.length);
        uint256 valuesLength = values.length;
        for (uint256 i = 0; i < valuesLength; ++i) {
            assert(builder.constraintMultipliers[i] == values[i]);
        }
    }

    function testSetMaxDegree() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setMaxDegree(builder, 42);
        assert(builder.maxDegree == 42);
    }

    function testFuzzSetMaxDegree(uint256 value) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setMaxDegree(builder, value);
        assert(builder.maxDegree == value);
    }

    function testSetAggregateEvaluation() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setAggregateEvaluation(builder, 42);
        assert(builder.aggregateEvaluation == 42);
    }

    function testFuzzSetAggregateEvaluation(uint256 value) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setAggregateEvaluation(builder, value);
        assert(builder.aggregateEvaluation == value);
    }

    function testSetRowMultipliersEvaluation() public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setRowMultipliersEvaluation(builder, 42);
        assert(builder.rowMultipliersEvaluation == 42);
    }

    function testFuzzSetRowMultipliersEvaluation(uint256 value) public pure {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        VerificationBuilder.__setRowMultipliersEvaluation(builder, value);
        assert(builder.rowMultipliersEvaluation == value);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testProduceZerosumConstraint() public {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory multipliers = new uint256[](3);
        multipliers[0] = 101;
        multipliers[1] = 103;
        multipliers[2] = 107;
        builder.constraintMultipliers = multipliers;
        builder.maxDegree = 3;
        builder.aggregateEvaluation = 211;

        VerificationBuilder.__produceZerosumConstraint(builder, 307, 0);
        assert(builder.aggregateEvaluation == 211 + 101 * 307);
        VerificationBuilder.__produceZerosumConstraint(builder, 311, 1);
        assert(builder.aggregateEvaluation == 211 + 101 * 307 + 103 * 311);
        VerificationBuilder.__produceZerosumConstraint(builder, 313, 2);
        assert(builder.aggregateEvaluation == 211 + 101 * 307 + 103 * 311 + 107 * 313);
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__produceZerosumConstraint(builder, 317, 3);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testProduceZerosumConstraintDegreeError() public {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        builder.maxDegree = 3;
        vm.expectRevert(Errors.ConstraintDegreeTooHigh.selector);
        VerificationBuilder.__produceZerosumConstraint(builder, 1, 4);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testFuzzProduceZerosumConstraint(uint256[] memory multipliers, uint256[] memory values) public {
        vm.assume(multipliers.length < values.length);
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        builder.constraintMultipliers = multipliers;
        builder.maxDegree = 3;
        builder.aggregateEvaluation = 0;

        uint256 length = multipliers.length;

        uint256 aggregate = 0;
        for (uint256 i = 0; i < length; ++i) {
            aggregate = addmod(aggregate, mulmod(multipliers[i], values[i], MODULUS), MODULUS);
        }
        for (uint256 i = 0; i < length; ++i) {
            VerificationBuilder.__produceZerosumConstraint(builder, values[i], 3);
        }
        assert(builder.aggregateEvaluation == aggregate);

        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__produceZerosumConstraint(builder, values[length], 3);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testProduceIdentityConstraint() public {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        uint256[] memory multipliers = new uint256[](3);
        multipliers[0] = 101;
        multipliers[1] = 103;
        multipliers[2] = 107;
        builder.constraintMultipliers = multipliers;
        builder.maxDegree = 4;
        builder.aggregateEvaluation = 211;
        builder.rowMultipliersEvaluation = 223;

        VerificationBuilder.__produceIdentityConstraint(builder, 307, 0);
        assert(builder.aggregateEvaluation == 211 + 223 * (101 * 307));
        VerificationBuilder.__produceIdentityConstraint(builder, 311, 1);
        assert(builder.aggregateEvaluation == 211 + 223 * (101 * 307 + 103 * 311));
        VerificationBuilder.__produceIdentityConstraint(builder, 313, 2);
        assert(builder.aggregateEvaluation == 211 + 223 * (101 * 307 + 103 * 311 + 107 * 313));
        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__produceIdentityConstraint(builder, 317, 3);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testProduceIdentityConstraintDegreeError() public {
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        builder.maxDegree = 3;
        vm.expectRevert(Errors.ConstraintDegreeTooHigh.selector);
        VerificationBuilder.__produceIdentityConstraint(builder, 1, 3);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testFuzzProduceIdentityConstraint(
        uint256[] memory multipliers,
        uint256[] memory values,
        uint256 rowMultipliersEvaluation
    ) public {
        vm.assume(multipliers.length < values.length);
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        builder.constraintMultipliers = multipliers;
        builder.maxDegree = 3;
        builder.aggregateEvaluation = 0;
        builder.rowMultipliersEvaluation = rowMultipliersEvaluation;

        uint256 length = multipliers.length;

        uint256 aggregate = 0;
        for (uint256 i = 0; i < length; ++i) {
            aggregate = addmod(aggregate, mulmod(multipliers[i], values[i], MODULUS), MODULUS);
        }
        aggregate = mulmod(aggregate, rowMultipliersEvaluation, MODULUS);
        for (uint256 i = 0; i < length; ++i) {
            VerificationBuilder.__produceIdentityConstraint(builder, values[i], 2);
        }
        assert(builder.aggregateEvaluation == aggregate);

        vm.expectRevert(Errors.EmptyQueue.selector);
        VerificationBuilder.__produceIdentityConstraint(builder, values[length], 2);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function testFuzzProduceMixedConstraints(
        uint256[] memory multipliers,
        uint256[] memory values,
        bool[] memory isZerosum,
        uint256 rowMultipliersEvaluation
    ) public {
        vm.assume(multipliers.length < values.length);
        vm.assume(multipliers.length < isZerosum.length);
        VerificationBuilder.Builder memory builder = VerificationBuilder.__builderNew();
        builder.constraintMultipliers = multipliers;
        builder.maxDegree = 3;
        builder.aggregateEvaluation = 0;
        builder.rowMultipliersEvaluation = rowMultipliersEvaluation;

        uint256 length = multipliers.length;

        uint256 aggregate = 0;
        for (uint256 i = 0; i < length; ++i) {
            if (isZerosum[i]) {
                aggregate = addmod(aggregate, mulmod(multipliers[i], values[i], MODULUS), MODULUS);
            } else {
                aggregate = addmod(
                    aggregate,
                    mulmod(mulmod(multipliers[i], values[i], MODULUS), rowMultipliersEvaluation, MODULUS),
                    MODULUS
                );
            }
        }
        for (uint256 i = 0; i < length; ++i) {
            if (isZerosum[i]) {
                VerificationBuilder.__produceZerosumConstraint(builder, values[i], 3);
            } else {
                VerificationBuilder.__produceIdentityConstraint(builder, values[i], 2);
            }
        }
        assert(builder.aggregateEvaluation == aggregate);

        vm.expectRevert(Errors.EmptyQueue.selector);
        if (isZerosum[length]) {
            VerificationBuilder.__produceZerosumConstraint(builder, values[length], 3);
        } else {
            VerificationBuilder.__produceIdentityConstraint(builder, values[length], 2);
        }
    }
}
