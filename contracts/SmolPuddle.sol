//SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./utils/SignatureValidator.sol";
import "./SafeERC20ERC721.sol";
import "./EIP712Order.sol";


enum Status {
  Open,
  Executed,
  Canceled
}

interface WETH is ERC20_ERC721 {
  function deposit() external payable;
}

contract SmolPuddle is ReentrancyGuard, Ownable, EIP712Order {
  using SafeERC20ERC721 for ERC20_ERC721;

  mapping(address => mapping(bytes32 => Status)) public status;
  WETH public immutable weth;

  constructor(WETH _weth, uint256 _chainID) EIP712Order(_chainID) {
    weth = _weth;
  }

  // Three events so we can have more indexed fields
  event OrderExecutedP1(
    bytes32 indexed order,
    address indexed seller,
    address indexed buyer
  );

  event OrderExecutedP2(
    OrderType indexed orderType,
    address indexed buyToken,
    uint256 indexed buyTokenIdOrAmount
  );

  event OrderExecutedP3(    
    address indexed sellToken,
    uint256 indexed sellTokenIdOrAmount,
    address[] feeRecipients,
    uint256[] feeAmounts
  );

  event OrderCanceled(
    bytes32 indexed order,
    address indexed seller

  );

  // Errors
  error OrderExpired();
  error InvalidSignature();
  error InvalidArrays();
  error OrderNotOpen();
  error InvalidPayment();
  error InvalidOrderType();

  /**
   * @notice Will cancel a given order
   * @param _hash Hash of the order to cancel
   */
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
  function swap(Order memory _order, bytes memory _signature) public payable nonReentrant returns (bool) {
    // Must not be expired
    if (block.timestamp > _order.expiration) {
      revert OrderExpired();
    }

    // Compute order hash
    bytes32 orderHash = EIP712Order.hash(_order);

    // Check user signature
    if (!SignatureValidator.isValidSignature(_order.seller, orderHash, _signature)) {
      revert InvalidSignature();
    }

    // Check if order is canceled or executed
    if (status[_order.seller][orderHash] != Status.Open) {
      revert OrderNotOpen();
    }

    // Switch order status to executed
    status[_order.seller][orderHash] = Status.Executed;

    // Currency to NFT trade (i.e. filling a NFT sell order)
    if (_order.orderType == OrderType.SellNFT) {
      // If buyer is paying directly with WETH
      address currencySender = msg.sender;

      // If buyer sends ETH, then ETH will be converted to WETH and send from this contract.
      if (_order.askToken == address(weth) && msg.value == _order.askTokenIdOrAmount) {
        weth.deposit{ value: _order.askTokenIdOrAmount }();
        currencySender = address(this);
      } else if (msg.value > 0) {
        // Amount of ETH must be either 0 or equal to _order.amount
        revert InvalidPayment();
      }

      // Execute all transfers
      uint256 totalFeePaid = _feePayment(_order.askToken, currencySender, _order.feeRecipients, _order.feeAmounts);
      uint256 revenueForNFT = _order.askTokenIdOrAmount - totalFeePaid;                         // Amount of currency NFT owner will receive after fee
      ERC20_ERC721(_order.askToken).safeTransferFrom(currencySender, _order.seller, revenueForNFT);           // Sending currency to seller
      ERC20_ERC721(_order.sellToken).safeTransferFrom(_order.seller, msg.sender, _order.sellTokenIdOrAmount); // Sending NFT to buyer

    // NFT to currency trade (i.e. filling an NFT buy order)
    } else if (_order.orderType == OrderType.BuyNFT)  {
      // Execute all transfers
      uint256 totalFeePaid = _feePayment(_order.sellToken, _order.seller, _order.feeRecipients, _order.feeAmounts);
      uint256 revenueForNFT = _order.sellTokenIdOrAmount - totalFeePaid;                      // Amount of currency NFT owner will receive after fee
      ERC20_ERC721(_order.sellToken).safeTransferFrom(_order.seller, msg.sender, revenueForNFT);            // Sending currency to NFT seller
      ERC20_ERC721(_order.askToken).safeTransferFrom(msg.sender, _order.seller, _order.askTokenIdOrAmount); // Sending NFT to who made an offer

    // NFT to NFT trade
    } else if (_order.orderType == OrderType.NftToNft) {
      if (msg.value > 0) { revert InvalidPayment(); }
      ERC20_ERC721(_order.askToken).safeTransferFrom(msg.sender, _order.seller, _order.askTokenIdOrAmount);
      ERC20_ERC721(_order.sellToken).safeTransferFrom(_order.seller, msg.sender, _order.sellTokenIdOrAmount);
    } else {
      revert InvalidOrderType();
    }

    // Emit events
    emit OrderExecutedP1(orderHash, _order.seller, msg.sender);
    emit OrderExecutedP2(_order.orderType, _order.sellToken, _order.sellTokenIdOrAmount);
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
  function _feePayment(address _currency, address _from, address[] memory _feeRecipients, uint256[] memory _feeAmounts) private returns (uint256 totalFeeAmount) {
    // Sanity check inputs
    if (_feeRecipients.length != _feeAmounts.length) {
      revert InvalidArrays();
    }

    // Transfer to fee recipients
    for (uint256 i = 0; i < _feeRecipients.length; i++) {
      totalFeeAmount -= _feeAmounts[i];
      ERC20_ERC721(_currency).safeTransferFrom(_from, _feeRecipients[i], _feeAmounts[i]);
    }

    return totalFeeAmount;
  }

  /**
   * @notice Will self-destruct the contract
   * @dev This will be used if a vulnerability is discovered to halt an attacker
   * @param _recipient Address that will receive stuck ETH, if any
   */
  function NUKE(address payable _recipient) external onlyOwner {
    selfdestruct(_recipient);
  }
}
