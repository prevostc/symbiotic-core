// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IBaseDelegator} from "./IBaseDelegator.sol";

/**
 * @title IIsolatedOperatorDelegator
 * @notice Interface for an isolated operator delegator that manages stake allocation per operator.
 *
 * @dev Stake Allocation and Proportional Reduction:
 * This delegator allows setting stake amounts for individual operators. When the total allocated
 * stake exceeds the available vault collateral, all operators' stakes are proportionally reduced
 * to ensure the sum doesn't exceed the available collateral.
 *
 * Example:
 * - Operator A allocated: 10 tokens
 * - Operator B allocated: 10 tokens
 * - Operator C allocated: 30 tokens
 * - Total allocated: 50 tokens, Vault collateral: 50 tokens → All operators get their full allocation
 *
 * After a withdrawal leaving only 10 tokens in the vault:
 * - Operator A effective stake: 10 * (10/50) = 2 tokens
 * - Operator B effective stake: 10 * (10/50) = 2 tokens
 * - Operator C effective stake: 30 * (10/50) = 6 tokens
 * - Total effective stake: 10 tokens (matches available collateral)
 *
 * All view functions return effective stakes (after proportional reduction if needed).
 */
interface IIsolatedOperatorDelegator is IBaseDelegator {
    error DuplicateRoleHolder();
    error ExceedsAvailableStake();
    error InsufficientFreeStake();
    error MissingRoleHolders();
    error ZeroAddressRoleHolder();

    /**
     * @notice Hints for a stake.
     * @param baseHints base hints
     * @param activeStakeHint hint for the active stake checkpoint
     * @param totalOperatorStakeHint hint for the total operator stake checkpoint
     * @param operatorStakeHint hint for the operator stake checkpoint
     * @param totalStakeHint hint for the total stake checkpoint
     */
    struct StakeHints {
        bytes baseHints;
        bytes activeStakeHint;
        bytes totalOperatorStakeHint;
        bytes operatorStakeHint;
        bytes totalStakeHint;
    }

    /**
     * @notice Initial parameters needed for an isolated operator delegator deployment.
     * @param baseParams base parameters for delegators' deployment
     * @param operatorStakeSetRoleHolders array of addresses of the initial OPERATOR_STAKE_SET_ROLE holders
     */
    struct InitParams {
        IBaseDelegator.BaseParams baseParams;
        address[] operatorStakeSetRoleHolders;
    }

    /**
     * @notice Emitted when an operator's allocated stake is set.
     * @param operator address of the operator
     * @param amount new allocated stake amount for the operator
     */
    event SetOperatorStake(address indexed operator, uint256 amount);

    /**
     * @notice Get an operator stake setter's role.
     * @return identifier of the operator stake setter role
     */
    function OPERATOR_STAKE_SET_ROLE() external view returns (bytes32);

    /**
     * @notice Get the sum of all operators' effective stake at a given timestamp using a hint.
     * @dev This returns the total effective stake after proportional reduction if needed.
     * @param timestamp time point to get the total effective stake at
     * @param hint hint for checkpoint index
     * @return total effective stake of all operators at the given timestamp
     */
    function totalOperatorStakeAt(
        uint48 timestamp,
        bytes memory hint
    ) external view returns (uint256);

    /**
     * @notice Get the sum of all operators' effective stake.
     * @dev This returns the total effective stake after proportional reduction if needed.
     * @return total effective stake of all operators
     */
    function totalOperatorStake() external view returns (uint256);

    /**
     * @notice Get an operator's effective stake at a given timestamp using a hint.
     * @dev This returns the effective stake after proportional reduction if needed.
     * @param operator address of the operator
     * @param timestamp time point to get the operator's effective stake at
     * @param hint hint for checkpoint index
     * @return effective stake of the operator at the given timestamp
     */
    function operatorStakeAt(
        address operator,
        uint48 timestamp,
        bytes memory hint
    ) external view returns (uint256);

    /**
     * @notice Get an operator's effective stake.
     * @dev This returns the effective stake after proportional reduction if needed.
     * @param operator address of the operator
     * @return effective stake of the operator
     */
    function operatorStake(address operator) external view returns (uint256);

    /**
     * @notice Set an operator's allocated stake amount.
     * @dev This sets the allocated amount for the operator. The actual effective stake may be
     *      proportionally reduced if the total allocated stake across all operators exceeds
     *      the available vault collateral.
     * @param operator address of the operator
     * @param amount new allocated stake amount for the operator
     * @dev Only an OPERATOR_STAKE_SET_ROLE holder can call this function.
     *      The total allocated stake cannot exceed the available vault collateral.
     */
    function setOperatorStake(address operator, uint256 amount) external;

    /**
     * @notice Get the amount of free (unassigned) stake available for assignment at a given timestamp.
     * @param timestamp time point to get the free stake at
     * @param hint hint for checkpoint index
     * @return amount of free stake at the timestamp
     */
    function freeStakeAt(
        uint48 timestamp,
        bytes memory hint
    ) external view returns (uint256);

    /**
     * @notice Get the amount of free (unassigned) stake available for assignment.
     * @return amount of free stake
     */
    function freeStake() external view returns (uint256);
}
