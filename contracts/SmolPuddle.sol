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
    bytes32 indexed order,
    address indexed seller,
    address indexed buyer
  );

  event OrderExecutedP2(
    CurrencyToken indexed currency,
    ERC20_ERC721 indexed buyToken,
    uint256 indexed buyTokenIdOrAmount
  );

  event OrderExecutedP3(    
    ERC20_ERC721 indexed sellToken,
    uint256 indexed sellTokenIdOrAmount,
    address[] feeRecipients,
    uint256[] feeAmounts
  );

  event OrderCanceled(
    bytes32 indexed order,
    address indexed seller

  );

  struct Order {
    address seller;              // Seller's address
    CurrencyToken currency;      // Indicate which asset is the currency, if any
    ERC20_ERC721 askToken;       // Token seller is requesting
    ERC20_ERC721 sellToken;      // Token address that is being sold
    uint256 askTokenIdOrAmount;  // ID or amount seller is requesting
    uint256 sellTokenIdOrAmount; // Id or amount seller is selling
    address[] feeRecipients;     // Array of who will receive fee for the trade
    uint256[] feeAmounts;        // Amount to be sent for respective fee recipient
    uint256 expiration;          // When the order expires
    bytes32 salt;                // Salt to prevent hash collision 
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

    // NFT to NFT trade
    if (_order.currency == CurrencyToken.None) {
      if (msg.value > 0) { revert InvalidPayment(); }
      _order.askToken.safeTransferFrom(msg.sender, _order.seller, _order.askTokenIdOrAmount);
      _order.sellToken.safeTransferFrom(_order.seller, msg.sender, _order.sellTokenIdOrAmount);

    // Currency to NFT trade (i.e. NFT purchase)
    } else if (_order.currency == CurrencyToken.Ask) {
      // If buyer is paying directly with WETH
      address currencySender = msg.sender;

      // If buyer sends ETH, then ETH will be converted to WETH and send from this contract.
      if (_order.askToken == weth && msg.value == _order.askTokenIdOrAmount) {
        weth.deposit{ value: _order.askTokenIdOrAmount }();
        currencySender = address(this);
      } else if (msg.value > 0) {
        // Amount of ETH must be either 0 or equal to _order.amount
        revert InvalidPayment();
      }

      // Execute all transfers
      uint256 totalFeePaid = _feePayment(_order.askToken, currencySender, _order.feeRecipients, _order.feeAmounts);
      uint256 revenueForNFT = _order.askTokenIdOrAmount - totalFeePaid;                         // Amount of currency NFT owner will receive after fee
      _order.askToken.safeTransferFrom(currencySender, _order.seller, revenueForNFT);           // Sending currency to seller
      _order.sellToken.safeTransferFrom(_order.seller, msg.sender, _order.sellTokenIdOrAmount); // Sending NFT to buyer

    // NFT to currency trade (i.e. NFT seller accepts an offer)
    } else {
      // Execute all transfers
      uint256 totalFeePaid = _feePayment(_order.sellToken, _order.seller, _order.feeRecipients, _order.feeAmounts);
      uint256 revenueForNFT = _order.sellTokenIdOrAmount - totalFeePaid;                      // Amount of currency NFT owner will receive after fee
      _order.sellToken.safeTransferFrom(_order.seller, msg.sender, revenueForNFT);            // Sending currency to NFT seller
      _order.askToken.safeTransferFrom(msg.sender, _order.seller, _order.askTokenIdOrAmount); // Sending NFT to who made an offer
    }

    // Emit events
    emit OrderExecutedP1(orderHash, _order.seller, msg.sender);
    emit OrderExecutedP2(_order.currency, _order.sellToken, _order.sellTokenIdOrAmount);
    emit OrderExecutedP3(_order.askToken, _order.askTokenIdOrAmount, _order.feeRecipients, _order.feeAmounts);

    // All done!
    return true;
  }

  /**
   * @notice Will pay the fee recipients
   * @param _currency      Token used as currency for fee payment
   * @param _from          Address who will pay the fee
   * @param _feeRecipients Array of addresses to pay the fees to
   * @param _feeAmounts    Array of amount of fees to pay to each corresponding fee recipient
   * @return totalFeeAmount Total amount of fee paid
   */
  function _feePayment(ERC20_ERC721 _currency, address _from, address[] memory _feeRecipients, uint256[] memory _feeAmounts) private returns (uint256 totalFeeAmount) {
    // Transfer to fee recipients
    for (uint256 i = 0; i < _feeRecipients.length; i++) {
      totalFeeAmount -= _feeAmounts[i];
      _currency.safeTransferFrom(_from, _feeRecipients[i], _feeAmounts[i]);
    }

    return totalFeeAmount;
  }
}
