// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import {BaseDelegator} from "./BaseDelegator.sol";

import {IBaseDelegator} from "../../interfaces/delegator/IBaseDelegator.sol";
import {IIsolatedOperatorDelegator} from "../../interfaces/delegator/IIsolatedOperatorDelegator.sol";
import {IVault} from "../../interfaces/vault/IVault.sol";

import {Checkpoints} from "../libraries/Checkpoints.sol";

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Time} from "@openzeppelin/contracts/utils/types/Time.sol";

contract IsolatedOperatorDelegator is
    BaseDelegator,
    IIsolatedOperatorDelegator
{
    using Checkpoints for Checkpoints.Trace256;
    using Math for uint256;

    /**
     * @inheritdoc IIsolatedOperatorDelegator
     */
    bytes32 public constant OPERATOR_STAKE_SET_ROLE =
        keccak256("OPERATOR_STAKE_SET_ROLE");

    mapping(address operator => Checkpoints.Trace256 stake)
        internal _operatorStake;

    // Total stake across all operators
    Checkpoints.Trace256 internal _totalOperatorStake;

    constructor(
        address networkRegistry,
        address vaultFactory,
        address operatorVaultOptInService,
        address operatorNetworkOptInService,
        address delegatorFactory,
        uint64 entityType
    )
        BaseDelegator(
            networkRegistry,
            vaultFactory,
            operatorVaultOptInService,
            operatorNetworkOptInService,
            delegatorFactory,
            entityType
        )
    {}

    /**
     * @notice Apply proportional reduction to allocated stake if needed.
     * @dev If total allocated stake exceeds available collateral, reduces the allocated amount proportionally.
     * @param allocated The allocated stake amount for a specific operator
     * @param activeStake The total active stake available in the vault
     * @param totalAllocated The total allocated stake across all operators
     * @return The effective stake after proportional reduction
     */
    function _applyProportionalReduction(
        uint256 allocated,
        uint256 activeStake,
        uint256 totalAllocated
    ) internal pure returns (uint256) {
        if (allocated == 0) {
            return 0;
        }

        // If total allocated stake exceeds available collateral, reduce proportionally
        if (totalAllocated > activeStake && totalAllocated > 0) {
            allocated = allocated.mulDiv(activeStake, totalAllocated);
        }

        return Math.min(allocated, activeStake);
    }

    /**
     * @inheritdoc IIsolatedOperatorDelegator
     */
    function totalOperatorStakeAt(
        uint48 timestamp,
        bytes memory hint
    ) public view returns (uint256) {
        uint256 totalAllocated = _totalOperatorStake.upperLookupRecent(
            timestamp,
            hint
        );
        uint256 activeStake = IVault(vault).activeStakeAt(timestamp, hint);

        // Return the minimum of allocated stake and available collateral
        return Math.min(totalAllocated, activeStake);
    }

    /**
     * @inheritdoc IIsolatedOperatorDelegator
     */
    function totalOperatorStake() public view returns (uint256) {
        uint256 totalAllocated = _totalOperatorStake.latest();
        uint256 activeStake = IVault(vault).activeStake();

        // Return the minimum of allocated stake and available collateral
        return Math.min(totalAllocated, activeStake);
    }

    /**
     * @inheritdoc IIsolatedOperatorDelegator
     */
    function operatorStakeAt(
        address operator,
        uint48 timestamp,
        bytes memory hint
    ) public view returns (uint256) {
        return
            _applyProportionalReduction(
                _operatorStake[operator].upperLookupRecent(timestamp, hint),
                IVault(vault).activeStakeAt(timestamp, hint),
                _totalOperatorStake.upperLookupRecent(timestamp, hint)
            );
    }

    /**
     * @inheritdoc IIsolatedOperatorDelegator
     */
    function operatorStake(address operator) public view returns (uint256) {
        return
            _applyProportionalReduction(
                _operatorStake[operator].latest(),
                IVault(vault).activeStake(),
                _totalOperatorStake.latest()
            );
    }

    /**
     * @inheritdoc IIsolatedOperatorDelegator
     */
    function freeStake() public view returns (uint256) {
        uint256 activeStake = IVault(vault).activeStake();
        uint256 totalEffective = totalOperatorStake();
        return activeStake > totalEffective ? activeStake - totalEffective : 0;
    }

    /**
     * @inheritdoc IIsolatedOperatorDelegator
     */
    function freeStakeAt(
        uint48 timestamp,
        bytes memory hint
    ) public view returns (uint256) {
        uint256 activeStake = IVault(vault).activeStakeAt(timestamp, hint);
        uint256 totalEffective = totalOperatorStakeAt(timestamp, hint);
        return activeStake > totalEffective ? activeStake - totalEffective : 0;
    }

    /**
     * @inheritdoc IIsolatedOperatorDelegator
     */
    function setOperatorStake(
        address operator,
        uint256 amount
    ) external onlyRole(OPERATOR_STAKE_SET_ROLE) {
        uint256 currentStake = _operatorStake[operator].latest();
        if (currentStake == amount) {
            revert AlreadySet();
        }

        // Calculate the new total operator stake
        uint256 currentTotalOperatorStake = _totalOperatorStake.latest();
        uint256 newTotalOperatorStake = currentTotalOperatorStake -
            currentStake +
            amount;

        // Check if the new total would exceed available stake
        uint256 activeStake = IVault(vault).activeStake();
        if (newTotalOperatorStake > activeStake) {
            revert ExceedsAvailableStake();
        }

        // Update the operator stake
        _operatorStake[operator].push(Time.timestamp(), amount);

        // Update the total operator stake
        _totalOperatorStake.push(Time.timestamp(), newTotalOperatorStake);

        emit SetOperatorStake(operator, amount);
    }

    function _stakeAt(
        bytes32,
        address operator,
        uint48 timestamp,
        bytes memory hints
    ) internal view override returns (uint256, bytes memory) {
        StakeHints memory stakeHints;
        if (hints.length > 0) {
            stakeHints = abi.decode(hints, (StakeHints));
        }

        uint256 effectiveStake = _applyProportionalReduction(
            _operatorStake[operator].upperLookupRecent(
                timestamp,
                stakeHints.operatorStakeHint
            ),
            IVault(vault).activeStakeAt(timestamp, stakeHints.activeStakeHint),
            _totalOperatorStake.upperLookupRecent(
                timestamp,
                stakeHints.totalOperatorStakeHint
            )
        );
        return (effectiveStake, stakeHints.baseHints);
    }

    function _stake(
        bytes32,
        address operator
    ) internal view override returns (uint256) {
        return
            _applyProportionalReduction(
                _operatorStake[operator].latest(),
                IVault(vault).activeStake(),
                _totalOperatorStake.latest()
            );
    }

    function _setMaxNetworkLimit(bytes32, uint256) internal override {
        // For isolated operator delegator, we don't have network limits
        // This function is inherited from BaseDelegator but not used in this implementation
        // We keep it empty to satisfy the interface
    }

    function __initialize(
        address,
        bytes memory data
    ) internal override returns (IBaseDelegator.BaseParams memory) {
        InitParams memory params = abi.decode(data, (InitParams));

        if (
            params.baseParams.defaultAdminRoleHolder == address(0) &&
            params.operatorStakeSetRoleHolders.length == 0
        ) {
            revert MissingRoleHolders();
        }

        for (uint256 i; i < params.operatorStakeSetRoleHolders.length; ++i) {
            if (params.operatorStakeSetRoleHolders[i] == address(0)) {
                revert ZeroAddressRoleHolder();
            }

            if (
                !_grantRole(
                    OPERATOR_STAKE_SET_ROLE,
                    params.operatorStakeSetRoleHolders[i]
                )
            ) {
                revert DuplicateRoleHolder();
            }
        }

        return params.baseParams;
    }
}
