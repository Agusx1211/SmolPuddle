//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

enum Status {
  Open,
  Executed,
  Canceled
}

interface WETH is IERC20 {
  function deposit() external payable;
}

contract SmolPuddle is ReentrancyGuard, Pausable {
  using SafeERC20 for IERC20;

  mapping(address => mapping(bytes32 => Status)) public status;
  WETH public immutable weth;

  constructor(WETH _weth) {
    weth = _weth;
  }

  event OrderExecutedP1(
    bytes32 indexed _order,
    address indexed _seller,
    address indexed _buyer
  );

  event OrderExecutedP2(
    IERC721 indexed _token,
    uint256 indexed _id,
    IERC20 _payment,
    uint256 _amount,
    address[] _feeRecipients,
    uint256[] _feeAmounts
  );

  event OrderCanceled(
    bytes32 indexed _order,
    address indexed _seller
  );

  error OrderExpired();
  error InalidSignature();
  error NotEnoughETH();
  error InvalidArrays();
  error OrderNotOpen();

  function cancel(bytes32 _hash) external {
    if (status[msg.sender][_hash] != Status.Open) {
      revert OrderNotOpen();
    }

    status[msg.sender][_hash] = Status.Canceled;
    emit OrderCanceled(_hash, msg.sender);
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

    // All ETH payments are WETH payments
    // signature must be on WETH, but buyer can pay in ETH if payment == 0
    IERC20 payment = address(_payment) == address(0) ? weth : _payment;

    // Scope orderHash due to stack limits

    {
      // Compute order hash
      bytes32 orderHash = keccak256(
        abi.encode(
          _nft,
          _tokenId,
          payment,
          _amount,
          _seller,
          _expiration,
          _salt,
          _feeRecipients,
          _feeAmounts
        )
      );

      // Emit events
      emit OrderExecutedP1(
        orderHash,
        _seller,
        msg.sender
      );

      emit OrderExecutedP2(
        _nft,
        _tokenId,
        _payment,
        _amount,
        _feeRecipients,
        _feeAmounts
      );

      // Check if order is canceled or executed
      if (status[_seller][orderHash] != Status.Open) {
        revert OrderNotOpen();
      }

      // Switch order status to executed
      status[_seller][orderHash] = Status.Executed;

      // Check user signature
      if (!SignatureChecker.isValidSignatureNow(_seller, orderHash, _signature)) {
        revert InalidSignature();
      }
    }

    // Transfer ERC721 Token
    _nft.transferFrom(_seller, msg.sender, _tokenId);

    // Wrap ETH into WETH if no token is defined
    // use WETH so recipients can't do weird things when they receive the payments
    address from = msg.sender;
    if (payment == _payment) {
      if (msg.value != _amount) {
        revert NotEnoughETH();
      }

      weth.deposit{ value: msg.value }();
      from = address(this);
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
