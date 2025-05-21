// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

interface INFE721 {
    function tokenValue(uint256 tokenId) external view returns (uint256);
}

contract REDEEM is IERC721Receiver, Ownable(msg.sender), ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public signer;
    address public ERC721;
    address public ERC20;
    address public PAYOUT;
    address private constant DEAD = 0x000000000000000000000000000000000000dEaD;
    bool public isRedeemable;

    mapping(address => bool) public isAddressBlacklisted;
    mapping(address => bool) public isAdmin;
    mapping(bytes => bool) public usedSig;
    mapping(address => mapping(uint256 => bool)) public isTokenIdBlacklisted;

    event Redeem(
        address indexed nfe,
        address indexed lastOwner,
        uint256 indexed tokenId,
        uint256 mniValue,
        uint256 timeStamp
    );
    event BlacklistedAddress(
        address indexed user,
        bool isBlacklisted,
        uint256 timeStamp
    );
    event SetIsRedeemable(bool isRedeemable);
    event AddOrRemoveAdmin(address indexed admin, bool isAdmin);
    event UpdateBlacklistedAddress(address indexed user, bool isBlacklisted);
    event UpdateBlacklistedTokenId(uint256 indexed tokenId, bool isBlacklisted);
    event UpdateCertificateAddress(address indexed newAddress);
    event UpdatePaymentAddress(address indexed newAddress);
    event UpdatePayoutAddress(address indexed newAddress);

    constructor() {
        ERC721 = 0x2C0ebDbF0f96293f4A5E13602DC37C424D978740;
        ERC20 = 0xfFe5413E1595fFb68564Fc2205a84D95656F228D;
        PAYOUT = 0x900c6f8AAcd4AA70F1477Be27CcbbD4bf9CC011E;
        signer = 0x143e5C4160Eaef1c01251D23F2A04F0b3e9d6c10;
        isRedeemable = true;

        emit UpdateCertificateAddress(ERC721);
        emit UpdatePaymentAddress(ERC20);
        emit UpdatePayoutAddress(PAYOUT);
        emit SetIsRedeemable(isRedeemable);
    }

    function splitSignature(
        bytes memory sig
    ) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function recoverSigner(
        bytes32 _hashedMessage,
        bytes memory sig
    ) internal pure returns (address) {
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = splitSignature(sig);
        return ecrecover(_hashedMessage, v, r, s);
    }

    function onERC721Received(
        address,
        address from,
        uint256 tokenId,
        bytes memory
    ) public override returns (bytes4) {
        emit Redeem(ERC721, from, tokenId, 0, block.timestamp);
        return this.onERC721Received.selector;
    }

    modifier onlyAdmin() {
        require(
            isAdmin[msg.sender] || msg.sender == owner(),
            "Only the admin or owner address can perform this action."
        );
        _;
    }

    function setIsRedeemable(bool _isRedeemable) public onlyAdmin {
        isRedeemable = _isRedeemable;
        emit SetIsRedeemable(_isRedeemable);
    }

    function addOrRemoveAdmin(address _admin, bool _isAdmin) public onlyOwner {
        isAdmin[_admin] = _isAdmin;
        emit AddOrRemoveAdmin(_admin, _isAdmin);
    }

    function updateBlacklistedAddress(
        address _user,
        bool _isBlacklisted
    ) public onlyAdmin {
        isAddressBlacklisted[_user] = _isBlacklisted;
        emit UpdateBlacklistedAddress(_user, _isBlacklisted);
    }

    function updateBlacklistedTokenId(
        uint256 tokenId,
        bool _isBlacklisted
    ) public onlyAdmin {
        isTokenIdBlacklisted[ERC721][tokenId] = _isBlacklisted;
        emit UpdateBlacklistedTokenId(tokenId, _isBlacklisted);
    }

    function updateCertificateAddress(address _address) public onlyOwner {
        ERC721 = _address;
        emit UpdateCertificateAddress(_address);
    }

    function updatePaymentAddress(address _address) public onlyOwner {
        ERC20 = _address;
        emit UpdatePaymentAddress(_address);
    }

    function updatePayoutAddress(address _address) public onlyOwner {
        PAYOUT = _address;
        emit UpdatePayoutAddress(_address);
    }

    function redeem(
        uint256 tokenId,
        uint256 _exp,
        bytes memory _sig
    ) public nonReentrant {
        require(!usedSig[_sig], "Signature already used");
        bytes32 _hashedMessage = keccak256(abi.encodePacked(msg.sender, _exp));
        require(
            recoverSigner(_hashedMessage, _sig) == signer,
            "Invalid signer"
        );
        require(isRedeemable, "Certificate is not redeemable.");
        require(
            !isAddressBlacklisted[msg.sender],
            "User address is blacklisted"
        );
        require(
            !isTokenIdBlacklisted[ERC721][tokenId],
            "This tokenID is blacklisted"
        );
        require(
            IERC721(ERC721).ownerOf(tokenId) == msg.sender,
            "You do not own this token"
        );
        require(
            IERC721(ERC721).isApprovedForAll(msg.sender, address(this)),
            "Contract must be approved"
        );

        INFE721 NFECERT = INFE721(ERC721);
        uint256 tokenValue = NFECERT.tokenValue(tokenId);

        IERC721(ERC721).safeTransferFrom(msg.sender, DEAD, tokenId);
        IERC20(ERC20).transferFrom(PAYOUT, msg.sender, tokenValue);

        emit Redeem(ERC721, msg.sender, tokenId, tokenValue, block.timestamp);
    }
}
