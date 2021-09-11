//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";


interface WETH is IERC20 {
  function deposit() external payable;
}

contract SmolPuddle is ReentrancyGuard, Pausable {
  using SafeERC20 for IERC20;

  mapping(address => mapping(bytes32 => bool)) public canceled;
  WETH public immutable weth;

  constructor(WETH _weth) {
    weth = _weth;
  }

  error OrderExpired();
  error InalidSignature();
  error OrderCanceled();
  error NotEnoughETH();
  error InvalidArrays();

  function cancel(bytes32 _hash) external {
    canceled[msg.sender][_hash] = true;
  }

  function swap(
    IERC721 _nft,
    uint256 _tokenId,
    IERC20 _payment,
    uint256 _amount,
    address _seller,
    uint256 _expiration,
    bytes32 _salt,
    address[] memory _feeRecipients,
    uint256[] memory _feeAmounts,
    bytes memory _signature
  ) public payable nonReentrant whenNotPaused returns (bool) {
    // Sanity check inputs
    uint256 feeRecipientsSize = _feeRecipients.length;
    if (feeRecipientsSize != _feeAmounts.length) {
      revert InvalidArrays();
    }

    // Must not be expired
    if (block.timestamp > _expiration) {
      revert OrderExpired();
    }

    // Compute order hash
    bytes32 orderHash = keccak256(
      abi.encode(
        _nft,
        _tokenId,
        _payment,
        _amount,
        _seller,
        _expiration,
        _salt,
        _feeRecipients,
        _feeAmounts
      )
    );

    // Check if order is canceled
    if (canceled[_seller][orderHash]) {
      revert OrderCanceled();
    }

    // Check user signature
    if (!SignatureChecker.isValidSignatureNow(_seller, orderHash, _signature)) {
      revert InalidSignature();
    }

    // Transfer ERC721 Token
    _nft.transferFrom(_seller, msg.sender, _tokenId);

    // Wrap ETH into WETH if no token is defined
    // use WETH so recipients can't do weird things when they receive the payments
    (IERC20 payment, address from) = address(_payment) == address(0) ? (_payment, msg.sender) : (weth, address(this));
    if (payment == weth) {
      if (msg.value != _amount) {
        revert NotEnoughETH();
      } 

      weth.deposit{ value: msg.value }();
    }

    // Seller receives amount - fees
    uint256 sellerAmount = _amount;

    // Transfer to fee recipients
    for (uint256 i = 0; i < feeRecipientsSize; i++) {
      uint256 amount = _feeAmounts[i];
      sellerAmount -= amount;
      payment.safeTransferFrom(from, _feeRecipients[i], amount);
    }

    // Transfer payments
    payment.safeTransferFrom(from, _seller, sellerAmount);

    // All done!
    return true;
  }
}
