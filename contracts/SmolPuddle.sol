//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

enum Status {
  Open,
  Executed,
  Canceled
}

interface ERC20_ERC721 {
  function transferFrom(address from, address to, uint256 idOrAmount) external;
}

interface WETH is ERC20_ERC721 {
  function deposit() external payable;
}

contract SmolPuddle is ReentrancyGuard, Pausable {
  using SafeERC20 for ERC20_ERC721;

  mapping(address => mapping(bytes32 => Status)) public status;
  WETH public immutable weth;

  constructor(WETH _weth) {
    weth = _weth;
  }

  // Three events so we can have more indexed fields
  event OrderExecutedP1(
    bytes32 indexed _order,
    address indexed _seller,
    address indexed _buyer
  );

  event OrderExecutedP2(
    ERC20_ERC721 indexed _buyToken,
    uint256 indexed _buyTokenIdOrAmount,
    ERC20_ERC721 indexed _sellToken
  );

  event OrderExecutedP3(    
    uint256 indexed _sellTokenIdOrAmount,
    address[] _feeRecipients,
    uint256[] _feeAmounts
  );

  event OrderCanceled(
    bytes32 indexed _order,
    address indexed _seller
  );

  struct Order {
    ERC20_ERC721 buyToken;
    uint256 buyTokenIdOrAmount;
    ERC20_ERC721 sellToken;
    uint256 sellTokenIdOrAmount;
    address seller;
    uint256 expiration;
    bytes32 salt;
    address[] feeRecipients;
    uint256[] feeAmounts;
    bytes signature;
  }

  error OrderExpired();
  error InalidSignature();
  error NotEnoughETH();
  error InvalidArrays();
  error OrderNotOpen();
  error InvalidPayment();

  function cancel(bytes32 _hash) external {
    if (status[msg.sender][_hash] != Status.Open) {
      revert OrderNotOpen();
    }

    status[msg.sender][_hash] = Status.Canceled;
    emit OrderCanceled(_hash, msg.sender);
  }

  function swap(Order memory _order) public payable nonReentrant whenNotPaused returns (bool) {
    // Sanity check inputs
    uint256 feeRecipientsSize = _order.feeRecipients.length;
    if (feeRecipientsSize != _order.feeAmounts.length) {
      revert InvalidArrays();
    }

    // Must not be expired
    if (block.timestamp > _order.expiration) {
      revert OrderExpired();
    }

    // Compute order hash
    bytes32 orderHash = keccak256(abi.encode(_order));

    // Check user signature
    if (!SignatureChecker.isValidSignatureNow(_order.seller, orderHash, _order.signature)) {
      revert InalidSignature();
    }

    // Check if order is canceled or executed
    if (status[_order.seller][orderHash] != Status.Open) {
      revert OrderNotOpen();
    }

    // Switch order status to executed
    status[_order.seller][orderHash] = Status.Executed;

    // Transfer the token purchased
    _order.buyToken.safeTransferFrom(_order.seller, msg.sender, _order.buyTokenIdOrAmount);

    // If user sends ETH, then ETH will be converted to WETH.
    address from = msg.sender;
    if (_order.payment == weth && msg.value > 0) {
      weth.deposit{ value: _order.amount }();
      from = address(this);
    } else if (msg.value > 0) {
      revert InvalidPayment();
    }

    // Seller receives amount - fees
    uint256 sellerAmount = _order.amount;

    // Transfer to fee recipients
    for (uint256 i = 0; i < feeRecipientsSize; i++) {
      sellerAmount -= _order.feeAmounts[i];
      _order.payment.safeTransferFrom(from, _order.feeRecipients[i], _order.feeAmounts[i]);
    }

    // Transfer payments
    _order.payment.safeTransferFrom(from, _order.seller, sellerAmount);

    // Emit events
    emit OrderExecutedP1(orderHash, _order.seller, msg.sender);
    emit OrderExecutedP2(_order.nft, _order.tokenId, _order.payment);
    emit OrderExecutedP3(_order.amount, _order.feeRecipients, _order.feeAmounts);

    // All done!
    return true;
  }
}
