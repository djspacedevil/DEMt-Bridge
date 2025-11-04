// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

// Direkte Imports von GitHub (OpenZeppelin v4.9, stabil)
// import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/token/ERC20/ERC20.sol";
// import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/token/ERC20/extensions/ERC20Burnable.sol";
// import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/security/Pausable.sol";
// import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/access/AccessControl.sol";
// import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/utils/cryptography/ECDSA.sol";
// import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.9.0/contracts/utils/cryptography/EIP712.sol";

contract DEMtToken is ERC20, ERC20Burnable, Pausable, AccessControl, EIP712 {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // EIP-712 typehash für unseren Mint-Request
    bytes32 private constant MINT_TYPEHASH =
        keccak256("Mint(address to,uint256 amount,uint256 nonce,uint256 deadline)");

    // Replay-Schutz
    mapping(bytes32 => bool) public usedMint;

    // Events für die Bridge
    event BridgeMint(address indexed to, uint256 amount);
    event BridgeBurn(address indexed user, uint256 amount);

    constructor(
        address admin_,
        address bridgeMinter_,
        string memory name_,
        string memory symbol_
    ) ERC20(name_, symbol_) EIP712("DEMtToken", "1") {
        // Admin: volle Kontrolle, aber kein Minter
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(PAUSER_ROLE, admin_);

        // Bridge: darf minten und brennen
        _grantRole(MINTER_ROLE, bridgeMinter_);
    }

    function decimals() public pure override returns (uint8) {
        return 8;
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // Klassisches Mint (nur Bridge)
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        require(!paused(), "Token is paused");
        require(amount > 0, "amount=0");
        _mint(to, amount);
        emit BridgeMint(to, amount);
    }

    // Mint mit EIP-712 Signatur (Bridge signiert Ticket, User zahlt Fee)
    function mintWithSig(
        address to,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "expired");
        require(amount > 0, "amount=0");

        bytes32 structHash = keccak256(
            abi.encode(MINT_TYPEHASH, to, amount, nonce, deadline)
        );
        bytes32 digest = _hashTypedDataV4(structHash);

        require(!usedMint[digest], "already-used");
        address signer = ECDSA.recover(digest, v, r, s);
        require(hasRole(MINTER_ROLE, signer), "bad-signer");

        usedMint[digest] = true;
        _mint(to, amount);
        emit BridgeMint(to, amount);
    }

    // Bridge-Burn: Bridge verbrennt DEMt im Auftrag des Users
    function bridgeBurnFrom(address account, uint256 amount) external onlyRole(MINTER_ROLE) {
        require(amount > 0, "amount=0");
        burnFrom(account, amount);
        emit BridgeBurn(account, amount);
    }

    // Hook: Alle Transfers blockieren, wenn pausiert
    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 amount
    ) internal override whenNotPaused {
        super._beforeTokenTransfer(from, to, amount);
    }
}
