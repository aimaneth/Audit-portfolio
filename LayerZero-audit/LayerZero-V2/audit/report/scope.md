# Audit Scope

## Repository
- **URL**: https://github.com/LayerZero-Labs/LayerZero-v2
- **Commit Hash**: [Latest commit hash to be added]

## In-Scope Contracts

### Core Protocol
1. Endpoint Contracts
   - `EndpointV2.sol` - Main endpoint implementation
   - `EndpointV2Alt.sol` - Alternative endpoint implementation
   - `EndpointV2View.sol` - View functions for endpoint
   - `EndpointV2ViewUpgradeable.sol` - Upgradeable view implementation

2. Messaging Contracts
   - `MessagingChannel.sol` - Channel management
   - `MessagingContext.sol` - Context handling
   - `MessageLibManager.sol` - Library management

### MessageLib
1. Base Implementation
   - `SimpleMessageLib.sol` - Basic message library
   - `BlockedMessageLib.sol` - Blocked message handling

2. ULN (Ultra Light Node) Components
   - `SendUlnBase.sol` - Base sending functionality
   - `ReceiveUlnBase.sol` - Base receiving functionality
   - `SendUln301.sol` - ULN 3.0.1 sending implementation
   - `SendUln302.sol` - ULN 3.0.2 sending implementation
   - `ReceiveUln302.sol` - ULN 3.0.2 receiving implementation

3. DVN (Decentralized Verifier Network)
   - `DVN.sol` - Main DVN implementation
   - `Worker.sol` - Worker implementation

### Libraries
1. Core Libraries
   - `AddressCast.sol` - Address manipulation
   - `Transfer.sol` - Token transfer utilities
   - `CalldataBytesLib.sol` - Calldata manipulation
   - `BitMaps.sol` - Bitmap operations
   - `PacketV1Codec.sol` - Packet encoding/decoding
   - `ExecutorOptions.sol` - Executor configuration

## Out of Scope
- Solana contracts
- Test files
- Mock contracts
- External dependencies (OpenZeppelin contracts)

## Areas of Focus
1. Cross-chain Message Security
   - Message validation and verification
   - DVN implementation security
   - Message delivery guarantees
   - Packet encoding/decoding safety

2. Protocol Architecture
   - Endpoint security and upgradability
   - MessageLib management and security
   - ULN implementation correctness
   - DVN security model

3. Access Controls
   - Role management
   - Privileged operations
   - Administrative functions
   - Upgrade mechanisms

4. Economic Security
   - Fee mechanisms
   - Protocol incentives
   - Economic attack vectors
   - Treasury management 