pragma solidity ^0.8.4;

contract EIP712Order {

  struct EIP712Domain {
    string  name;
    uint256 chainId;
    address verifyingContract;
  }

  enum OrderType {
    Invalid,
    NftToNft,
    BuyNFT,
    SellNFT
  }

  // Order structure
  struct Order {
    address seller;              // Seller's address
    OrderType orderType;         // Indicates which order this is (Nft -> NFT, token -> NFT or NFT -> token)
    address askToken;            // Token seller is requesting
    address sellToken;           // Token address that is being sold
    uint256 askTokenIdOrAmount;  // ID or amount seller is requesting
    uint256 sellTokenIdOrAmount; // Id or amount seller is selling
    address[] feeRecipients;     // Array of who will receive fee for the trade
    uint256[] feeAmounts;        // Amount to be sent for respective fee recipient
    uint256 expiration;          // When the order expires
    bytes32 salt;                // Salt to prevent hash collision 
  }

  // EIP-712 constants
  string constant internal EIP191_HEADER = "\x19\x01";

  bytes32 constant DOMAIN_SEPARATOR_TYPEHASH = keccak256(
    "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
  );

  bytes32 constant ORDER_TYPEHASH = keccak256(abi.encodePacked(
    "Order(",
    "address seller,",
    "uint256 orderType,",
    "address askToken,",
    "address sellToken,",
    "uint256 askTokenIdOrAmount,",
    "uint256 sellTokenIdOrAmount,",
    "address[] feeRecipients,",
    "uint256[] feeAmounts,",
    "uint256 expiration,",
    "uint256 salt",
    ")"
  ));

  bytes32 immutable public EIP712_DOMAIN_HASH;

  constructor (uint256 _chaindID) {
    EIP712_DOMAIN_HASH = keccak256(abi.encodePacked(
      DOMAIN_SEPARATOR_TYPEHASH,
      keccak256(bytes("Smol Puddle")),
      _chaindID,
      uint256(uint160(address(this)))
    ));
  }

  function hash(Order memory _order) public view returns (bytes32) {
    bytes32 orderStructHash = keccak256(abi.encodePacked(
      ORDER_TYPEHASH,
      uint256(uint160(_order.seller)),
      uint256(_order.orderType),
      uint256(uint160(_order.askToken)),
      uint256(uint160(_order.sellToken)),
      _order.askTokenIdOrAmount,
      _order.sellTokenIdOrAmount,
      keccak256(abi.encodePacked(_order.feeRecipients)),
      keccak256(abi.encodePacked(_order.feeAmounts)),
      _order.expiration,
      _order.salt
    ));

    return keccak256(abi.encodePacked(
      EIP191_HEADER,
      EIP712_DOMAIN_HASH,
      orderStructHash
    ));
  }
}
