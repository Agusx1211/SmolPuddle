//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import "./SafeERC20ERC721.sol";

enum Status {
  Open,
  Executed,
  Canceled
}

enum CurrencyToken {
  Ask,
  Sell,
  None
}

interface WETH is ERC20_ERC721 {
  function deposit() external payable;
}

contract SmolPuddle is ReentrancyGuard, Pausable {
  using SafeERC20ERC721 for ERC20_ERC721;

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
    uint256 indexed _buyTokenIdOrAmount
  );

  event OrderExecutedP3(    
    ERC20_ERC721 indexed _sellToken,
    uint256 indexed _sellTokenIdOrAmount,
    address[] _feeRecipients,
    uint256[] _feeAmounts
  );

  event OrderCanceled(
    bytes32 indexed _order,
    address indexed _seller
  );

  struct Order {
    ERC20_ERC721 askToken;       // Token seller is requesting
    uint256 askTokenIdOrAmount;  // ID or amount seller is requesting
    ERC20_ERC721 sellToken;      // Token address that is being sold
    uint256 sellTokenIdOrAmount; // Id or amount seller is selling
    CurrencyToken currency;      // Indicate which asset is the currency, if any
    address seller;              // Seller's address
    uint256 expiration;          // When the order expires
    bytes32 salt;                // Salt to prevent hash collision 
    address[] feeRecipients;     // Array of who will receive fee for the trade
    uint256[] feeAmounts;        // Amount to be sent for respective fee recipient
  }

  error OrderExpired();
  error InvalidSignature();
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

  /**
   * @notice Will fill an order
   * @param _order     Order to fill
   * @param _signature Signature associated with given order
   */

  function swap(Order memory _order, bytes memory _signature) public payable nonReentrant whenNotPaused returns (bool) {
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
    if (!SignatureChecker.isValidSignatureNow(_order.seller, orderHash, _signature)) {
      revert InvalidSignature();
    }

    // Check if order is canceled or executed
    if (status[_order.seller][orderHash] != Status.Open) {
      revert OrderNotOpen();
    }

    // Switch order status to executed
    status[_order.seller][orderHash] = Status.Executed;

    // If currency is asked by seller, then msg.sender is the one that needs to provide the currency
    address currencySender = _order.currency == CurrencyToken.Ask ? msg.sender : _order.seller;

    // If buyer sends ETH, then ETH will be converted to WETH and send from this contract.
    if (_order.askToken == weth && msg.value == _order.askTokenIdOrAmount) {
      weth.deposit{ value: _order.askTokenIdOrAmount }();
      currencySender = address(this);
    } else if (msg.value > 0) {
      // Amount of ETH must be either 0 or equal to _order.amount
      revert InvalidPayment();
    }

    // Check if either asset is a currency to pay for fees
    uint256 totalFeeAmount;

    // Only enfore fees when there is a currency involved
    if (_order.currency != CurrencyToken.None) {
      // Check which of the token is the currency used to pay fees with
      ERC20_ERC721 currency = _order.currency == CurrencyToken.Ask ? _order.askToken : _order.sellToken;

      // Transfer to fee recipients
      for (uint256 i = 0; i < feeRecipientsSize; i++) {
        totalFeeAmount -= _order.feeAmounts[i];
        currency.safeTransferFrom(currencySender, _order.feeRecipients[i], _order.feeAmounts[i]);
      }
    }

    // NFT seller is always the one that will pay the fee, unless it's an NFT <> NFT trade
    // If msg.sender is NFT buyer (i.e. currency is asked), then substract from what needs to be sent from buyer to seller
    // If msg.sender is NFT seller (i.e. currency is sold), then substract amount of currency the NFT owner will receive
    uint256 askIdOrAmount = _order.currency == CurrencyToken.Ask ? _order.askTokenIdOrAmount - totalFeeAmount : _order.askTokenIdOrAmount;
    uint256 sellIdOrAmount = _order.currency == CurrencyToken.Sell ? _order.sellTokenIdOrAmount - totalFeeAmount: _order.sellTokenIdOrAmount;
    
    // Transfer asset asked to seller (below lines added for clarity)
    // If currency is requested by seller, then sender is currencySender
    // Else if NFT is requeste by seller, then sender is msg.sender
    address askTokenSender = _order.currency == CurrencyToken.Ask ? currencySender : msg.sender; 
    _order.askToken.safeTransferFrom(askTokenSender, _order.seller, askIdOrAmount);

    // Transfer purchased asset to buyer
    _order.sellToken.safeTransferFrom(_order.seller, msg.sender, sellIdOrAmount);

    // Emit events
    emit OrderExecutedP1(orderHash, _order.seller, msg.sender);
    emit OrderExecutedP2(_order.sellToken, _order.sellTokenIdOrAmount);
    emit OrderExecutedP3(_order.askToken, _order.askTokenIdOrAmount, _order.feeRecipients, _order.feeAmounts);

    // All done!
    return true;
  }
}
