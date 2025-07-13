// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";

import {VaultFactory} from "../../src/contracts/VaultFactory.sol";
import {DelegatorFactory} from "../../src/contracts/DelegatorFactory.sol";
import {SlasherFactory} from "../../src/contracts/SlasherFactory.sol";
import {NetworkRegistry} from "../../src/contracts/NetworkRegistry.sol";
import {OperatorRegistry} from "../../src/contracts/OperatorRegistry.sol";
import {MetadataService} from "../../src/contracts/service/MetadataService.sol";
import {NetworkMiddlewareService} from "../../src/contracts/service/NetworkMiddlewareService.sol";
import {OptInService} from "../../src/contracts/service/OptInService.sol";

import {Vault} from "../../src/contracts/vault/Vault.sol";
import {IsolatedOperatorDelegator} from "../../src/contracts/delegator/IsolatedOperatorDelegator.sol";
import {Slasher} from "../../src/contracts/slasher/Slasher.sol";

import {IVault} from "../../src/interfaces/vault/IVault.sol";
import {IIsolatedOperatorDelegator} from "../../src/interfaces/delegator/IIsolatedOperatorDelegator.sol";
import {IBaseDelegator} from "../../src/interfaces/delegator/IBaseDelegator.sol";
import {ISlasher} from "../../src/interfaces/slasher/ISlasher.sol";
import {IBaseSlasher} from "../../src/interfaces/slasher/IBaseSlasher.sol";

import {Token} from "../mocks/Token.sol";
import {VaultConfigurator} from "../../src/contracts/VaultConfigurator.sol";
import {IVaultConfigurator} from "../../src/interfaces/IVaultConfigurator.sol";

import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {Subnetwork} from "../../src/contracts/libraries/Subnetwork.sol";

contract IsolatedOperatorDelegatorTest is Test {
    using Math for uint256;
    using Subnetwork for bytes32;
    using Subnetwork for address;

    address owner;
    address alice;
    uint256 alicePrivateKey;
    address bob;
    uint256 bobPrivateKey;
    address carol;
    uint256 carolPrivateKey;

    VaultFactory vaultFactory;
    DelegatorFactory delegatorFactory;
    SlasherFactory slasherFactory;
    NetworkRegistry networkRegistry;
    OperatorRegistry operatorRegistry;
    MetadataService operatorMetadataService;
    MetadataService networkMetadataService;
    NetworkMiddlewareService networkMiddlewareService;
    OptInService operatorVaultOptInService;
    OptInService operatorNetworkOptInService;

    Token collateral;
    VaultConfigurator vaultConfigurator;
    Vault vault;
    IsolatedOperatorDelegator delegator;
    Slasher slasher;

    function setUp() public {
        owner = address(this);
        (alice, alicePrivateKey) = makeAddrAndKey("alice");
        (bob, bobPrivateKey) = makeAddrAndKey("bob");
        (carol, carolPrivateKey) = makeAddrAndKey("carol");

        vaultFactory = new VaultFactory(owner);
        delegatorFactory = new DelegatorFactory(owner);
        slasherFactory = new SlasherFactory(owner);
        networkRegistry = new NetworkRegistry();
        operatorRegistry = new OperatorRegistry();
        operatorMetadataService = new MetadataService(
            address(operatorRegistry)
        );
        networkMetadataService = new MetadataService(address(networkRegistry));
        networkMiddlewareService = new NetworkMiddlewareService(
            address(networkRegistry)
        );
        operatorVaultOptInService = new OptInService(
            address(operatorRegistry),
            address(vaultFactory),
            "OperatorVaultOptInService"
        );
        operatorNetworkOptInService = new OptInService(
            address(operatorRegistry),
            address(networkRegistry),
            "OperatorNetworkOptInService"
        );

        address vaultImpl = address(
            new Vault(
                address(delegatorFactory),
                address(slasherFactory),
                address(vaultFactory)
            )
        );
        vaultFactory.whitelist(vaultImpl);

        address isolatedOperatorDelegatorImpl = address(
            new IsolatedOperatorDelegator(
                address(networkRegistry),
                address(vaultFactory),
                address(operatorVaultOptInService),
                address(operatorNetworkOptInService),
                address(delegatorFactory),
                delegatorFactory.totalTypes()
            )
        );
        delegatorFactory.whitelist(isolatedOperatorDelegatorImpl);

        address slasherImpl = address(
            new Slasher(
                address(vaultFactory),
                address(networkMiddlewareService),
                address(slasherFactory),
                slasherFactory.totalTypes()
            )
        );
        slasherFactory.whitelist(slasherImpl);

        collateral = new Token("Collateral");

        vaultConfigurator = new VaultConfigurator(
            address(vaultFactory),
            address(delegatorFactory),
            address(slasherFactory)
        );

        (vault, delegator) = _getVaultAndDelegator(1 days);
    }

    function test_Create(uint48 epochDuration) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));

        (vault, delegator) = _getVaultAndDelegator(epochDuration);

        assertEq(address(delegator.vault()), address(vault));
        assertEq(delegator.stakeAt(alice.subnetwork(0), alice, 0, ""), 0);
        assertEq(delegator.stake(alice.subnetwork(0), alice), 0);
        assertEq(
            delegator.OPERATOR_STAKE_SET_ROLE(),
            keccak256("OPERATOR_STAKE_SET_ROLE")
        );
        assertEq(delegator.totalOperatorStakeAt(0, ""), 0);
        assertEq(delegator.totalOperatorStake(), 0);
        assertEq(delegator.operatorStakeAt(alice, 0, ""), 0);
        assertEq(delegator.operatorStake(alice), 0);
        assertEq(delegator.freeStakeAt(0, ""), 0);
        assertEq(delegator.freeStake(), 0);
    }

    function test_CreateRevertMissingRoleHolders() public {
        address[] memory operatorStakeSetRoleHolders = new address[](0);

        vm.expectRevert(IIsolatedOperatorDelegator.MissingRoleHolders.selector);
        delegatorFactory.create(
            0,
            abi.encode(
                address(vault),
                abi.encode(
                    IIsolatedOperatorDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: address(0),
                            hook: address(0),
                            hookSetRoleHolder: address(0)
                        }),
                        operatorStakeSetRoleHolders: operatorStakeSetRoleHolders
                    })
                )
            )
        );
    }

    function test_CreateRevertZeroAddressRoleHolder() public {
        address[] memory operatorStakeSetRoleHolders = new address[](1);
        operatorStakeSetRoleHolders[0] = address(0);

        vm.expectRevert(
            IIsolatedOperatorDelegator.ZeroAddressRoleHolder.selector
        );
        delegatorFactory.create(
            0,
            abi.encode(
                address(vault),
                abi.encode(
                    IIsolatedOperatorDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: bob,
                            hook: address(0),
                            hookSetRoleHolder: address(0)
                        }),
                        operatorStakeSetRoleHolders: operatorStakeSetRoleHolders
                    })
                )
            )
        );
    }

    function test_CreateRevertDuplicateRoleHolder() public {
        address[] memory operatorStakeSetRoleHolders = new address[](2);
        operatorStakeSetRoleHolders[0] = bob;
        operatorStakeSetRoleHolders[1] = bob;

        vm.expectRevert(
            IIsolatedOperatorDelegator.DuplicateRoleHolder.selector
        );
        delegatorFactory.create(
            0,
            abi.encode(
                address(vault),
                abi.encode(
                    IIsolatedOperatorDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: bob,
                            hook: address(0),
                            hookSetRoleHolder: address(0)
                        }),
                        operatorStakeSetRoleHolders: operatorStakeSetRoleHolders
                    })
                )
            )
        );
    }

    function test_SetOperatorStake(
        uint48 epochDuration,
        uint256 amount1,
        uint256 amount2,
        uint256 amount3,
        uint256 totalAmount
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));
        amount1 = bound(amount1, 1, 100e18);
        amount2 = bound(amount2, 1, 100e18);
        amount3 = bound(amount3, 1, 100e18);
        totalAmount = bound(totalAmount, 1, 100_000e18);

        uint256 blockTimestamp = block.timestamp;

        (vault, delegator) = _getVaultAndDelegator(epochDuration);

        // deposit enough collateral to cover the total amount
        _deposit(alice, amount1 + amount2 + amount3);

        _setOperatorStake(alice, alice, amount1);
        _setOperatorStake(alice, bob, amount2);
        _setOperatorStake(alice, carol, amount3);

        // apply proportional reduction if the total amount is less than the available collateral
        uint256 totalAllocated = amount1 + amount2 + amount3;
        if (totalAllocated > totalAmount && totalAmount > 0) {
            amount1 = amount1.mulDiv(totalAmount, totalAllocated);
            amount2 = amount2.mulDiv(totalAmount, totalAllocated);
            amount3 = amount3.mulDiv(totalAmount, totalAllocated);

            // withdraw the excess collateral
            _withdraw(alice, totalAllocated - totalAmount);
        }

        assertEq(
            delegator.operatorStakeAt(alice, uint48(blockTimestamp), ""),
            amount1,
            "alice operator stake at 0"
        );
        assertEq(
            delegator.operatorStake(alice),
            amount1,
            "alice operator stake 0"
        );
        assertEq(
            delegator.operatorStakeAt(bob, uint48(blockTimestamp), ""),
            amount2,
            "bob operator stake at 0"
        );
        assertEq(delegator.operatorStake(bob), amount2, "bob operator stake 0");
        assertEq(
            delegator.operatorStakeAt(carol, uint48(blockTimestamp), ""),
            amount3,
            "carol operator stake at 0"
        );
        assertEq(
            delegator.operatorStake(carol),
            amount3,
            "carol operator stake 0"
        );

        assertEq(
            delegator.totalOperatorStakeAt(uint48(blockTimestamp), ""),
            Math.min(amount1 + amount2 + amount3, totalAmount),
            "total operator stake at 0"
        );
        assertEq(
            delegator.totalOperatorStake(),
            Math.min(amount1 + amount2 + amount3, totalAmount),
            "total operator stake 0"
        );
    }

    function test_SetOperatorStakeRevertExceedsAvailableStake(
        uint48 epochDuration,
        uint256 depositAmount,
        uint256 stakeAmount
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));
        depositAmount = bound(depositAmount, 1, 100 * 10 ** 18);
        stakeAmount = bound(stakeAmount, depositAmount + 1, type(uint256).max);

        (vault, delegator) = _getVaultAndDelegator(epochDuration);

        _deposit(alice, depositAmount);

        vm.expectRevert(
            IIsolatedOperatorDelegator.ExceedsAvailableStake.selector
        );
        _setOperatorStake(alice, alice, stakeAmount);
    }

    function test_SetOperatorStakeRevertAlreadySet(
        uint48 epochDuration,
        uint256 amount
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));
        amount = bound(amount, 1, 100 * 10 ** 18);

        (vault, delegator) = _getVaultAndDelegator(epochDuration);

        _deposit(alice, amount);
        _setOperatorStake(alice, alice, amount);

        vm.expectRevert(IBaseDelegator.AlreadySet.selector);
        _setOperatorStake(alice, alice, amount);
    }

    function test_FreeStake(
        uint48 epochDuration,
        uint256 depositAmount,
        uint256 stakeAmount
    ) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));
        depositAmount = bound(depositAmount, 1, 100 * 10 ** 18);
        stakeAmount = bound(stakeAmount, 1, depositAmount);

        (vault, delegator) = _getVaultAndDelegator(epochDuration);

        _deposit(alice, depositAmount);

        assertEq(delegator.freeStake(), depositAmount);
        assertEq(
            delegator.freeStakeAt(uint48(block.timestamp), ""),
            depositAmount
        );

        _setOperatorStake(alice, alice, stakeAmount);

        assertEq(delegator.freeStake(), depositAmount - stakeAmount);
        assertEq(
            delegator.freeStakeAt(uint48(block.timestamp), ""),
            depositAmount - stakeAmount
        );
    }

    function test_AccessControl(uint48 epochDuration, uint256 amount) public {
        epochDuration = uint48(bound(epochDuration, 1, 50 weeks));
        amount = bound(amount, 1, 100 * 10 ** 18);

        (vault, delegator) = _getVaultAndDelegator(epochDuration);

        _deposit(alice, amount);

        // Test that non-role holder cannot set operator stake
        vm.prank(bob);
        vm.expectRevert();
        delegator.setOperatorStake(alice, amount);

        // Test that role holder can set operator stake
        _setOperatorStake(alice, alice, amount);
        assertEq(delegator.operatorStake(alice), amount);
    }

    function _getVaultAndDelegator(
        uint48 epochDuration
    ) internal returns (Vault, IsolatedOperatorDelegator) {
        address[] memory operatorStakeSetRoleHolders = new address[](1);
        operatorStakeSetRoleHolders[0] = alice;

        (address vault_, address delegator_, ) = vaultConfigurator.create(
            IVaultConfigurator.InitParams({
                version: vaultFactory.lastVersion(),
                owner: alice,
                vaultParams: abi.encode(
                    IVault.InitParams({
                        collateral: address(collateral),
                        burner: address(0xdEaD),
                        epochDuration: epochDuration,
                        depositWhitelist: false,
                        isDepositLimit: false,
                        depositLimit: 0,
                        defaultAdminRoleHolder: alice,
                        depositWhitelistSetRoleHolder: alice,
                        depositorWhitelistRoleHolder: alice,
                        isDepositLimitSetRoleHolder: alice,
                        depositLimitSetRoleHolder: alice
                    })
                ),
                delegatorIndex: 0,
                delegatorParams: abi.encode(
                    IIsolatedOperatorDelegator.InitParams({
                        baseParams: IBaseDelegator.BaseParams({
                            defaultAdminRoleHolder: alice,
                            hook: address(0),
                            hookSetRoleHolder: alice
                        }),
                        operatorStakeSetRoleHolders: operatorStakeSetRoleHolders
                    })
                ),
                withSlasher: false,
                slasherIndex: 0,
                slasherParams: abi.encode(
                    ISlasher.InitParams({
                        baseParams: IBaseSlasher.BaseParams({
                            isBurnerHook: false
                        })
                    })
                )
            })
        );

        return (Vault(vault_), IsolatedOperatorDelegator(delegator_));
    }

    function _deposit(
        address user,
        uint256 amount
    ) internal returns (uint256 depositedAmount, uint256 mintedShares) {
        collateral.transfer(user, amount);
        vm.startPrank(user);
        collateral.approve(address(vault), amount);
        (depositedAmount, mintedShares) = vault.deposit(user, amount);
        vm.stopPrank();
    }

    function _withdraw(
        address user,
        uint256 amount
    ) internal returns (uint256 burnedShares, uint256 mintedShares) {
        vm.startPrank(user);
        (burnedShares, mintedShares) = vault.withdraw(user, amount);
        vm.stopPrank();
    }

    function _claim(
        address user,
        uint256 epoch
    ) internal returns (uint256 amount) {
        vm.startPrank(user);
        amount = vault.claim(user, epoch);
        vm.stopPrank();
    }

    function _claimBatch(
        address user,
        uint256[] memory epochs
    ) internal returns (uint256 amount) {
        vm.startPrank(user);
        amount = vault.claimBatch(user, epochs);
        vm.stopPrank();
    }

    function _setOperatorStake(
        address user,
        address operator,
        uint256 amount
    ) internal {
        vm.prank(user);
        delegator.setOperatorStake(operator, amount);
    }
}
