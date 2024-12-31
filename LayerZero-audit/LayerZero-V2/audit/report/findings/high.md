# High Severity Findings

## [H-01] Token Configuration Race Condition Can Lead to Locked Funds

### Description
In the `EndpointV2.sol` contract, there exists a race condition between token configuration changes and message sending that could lead to locked funds. The issue occurs in the interaction between `setLzToken` and `send`/`quote` functions.

When a user sends a message with `payInLzToken = true`, the contract checks if `lzToken` is set:
```solidity
if (_params.payInLzToken && lzToken == address(0x0)) revert Errors.LZ_LzTokenUnavailable();
```

However, if the `lzToken` address is changed by the owner between the time a user initiates a transaction and when it's mined, several issues can occur:
1. User's transaction could revert if token is set to zero address
2. User's tokens could get locked in the contract if fee calculation uses old token but refund uses new token
3. Message could be sent with incorrect fee token, leading to economic issues

### Impact
- Users could lose funds if tokens get locked in the contract
- Messages could be sent with incorrect fee calculations
- System could become temporarily unusable during token transitions

### Proof of Concept
```solidity
// 1. Initial state: lzToken = TokenA
// 2. User calls send() with payInLzToken = true, approving TokenA
// 3. Before user's tx is mined, owner calls setLzToken(TokenB)
// 4. User's tx is mined:
//    - Contract checks TokenA balance (old approval)
//    - Calculates fees using TokenB (new token)
//    - TokenA gets locked in contract
//    - User needs TokenB for actual fee payment

function setLzToken(address _lzToken) public virtual onlyOwner {
    lzToken = _lzToken;  // No protection against active messages
    emit LzTokenSet(_lzToken);
}

function send(MessagingParams calldata _params, address _refundAddress) external payable {
    if (_params.payInLzToken && lzToken == address(0x0)) 
        revert Errors.LZ_LzTokenUnavailable();
    // ... rest of the function
}
```

### Recommended Mitigation
1. Implement a timelock for token changes:
```solidity
uint256 public constant TOKEN_CHANGE_DELAY = 7 days;
address public pendingLzToken;
uint256 public pendingLzTokenTimestamp;

function proposeLzToken(address _newLzToken) external onlyOwner {
    pendingLzToken = _newLzToken;
    pendingLzTokenTimestamp = block.timestamp;
    emit LzTokenChangeProposed(_newLzToken);
}

function applyLzToken() external {
    require(block.timestamp >= pendingLzTokenTimestamp + TOKEN_CHANGE_DELAY, "Timelock not expired");
    lzToken = pendingLzToken;
    emit LzTokenSet(pendingLzToken);
}
```

2. Add version control for token changes:
```solidity
uint256 public lzTokenVersion;

function setLzToken(address _lzToken) public virtual onlyOwner {
    lzToken = _lzToken;
    lzTokenVersion++;
    emit LzTokenSet(_lzToken, lzTokenVersion);
}

function send(MessagingParams calldata _params, address _refundAddress, uint256 _expectedTokenVersion) external {
    require(lzTokenVersion == _expectedTokenVersion, "Token version mismatch");
    // ... rest of the function
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [H-02] Insufficient Packet Validation in SimpleMessageLib Enables Malicious Messages

### Description
The `SimpleMessageLib.sol` contract's `validatePacket` function lacks crucial packet format and content validation. The current implementation only verifies the caller's whitelist status and performs basic endpoint verification, without validating the packet structure, size, or content format.

```solidity
function validatePacket(bytes calldata packetBytes) external {
    if (whitelistCaller != address(0x0) && msg.sender != whitelistCaller) {
        revert OnlyWhitelistCaller();
    }
    Origin memory origin = Origin(packetBytes.srcEid(), packetBytes.sender(), packetBytes.nonce());
    ILayerZeroEndpointV2(endpoint).verify(origin, packetBytes.receiverB20(), keccak256(packetBytes.payload()));
}
```

This lack of validation could allow:
1. Malformed packets to be processed
2. Invalid packet versions to be accepted
3. Maliciously crafted packets to bypass security checks
4. Memory corruption through invalid packet sizes

### Impact
- Potential execution of malicious cross-chain messages
- Possible DoS through malformed packets
- Risk of memory corruption in packet processing
- Bypass of security checks through crafted packets

### Proof of Concept
```solidity
contract PacketValidationExploit {
    function exploitValidation(address messageLib) external {
        // 1. Create malformed packet with incorrect size
        bytes memory malformedPacket = new bytes(1); // Too small for valid packet
        
        // 2. Or create packet with invalid version
        bytes memory invalidVersionPacket = abi.encodePacked(
            uint8(99),  // Invalid version
            bytes32(0), // srcEid
            bytes32(0)  // Rest of packet
        );
        
        // 3. Both packets would pass validation
        SimpleMessageLib(messageLib).validatePacket(malformedPacket);
        SimpleMessageLib(messageLib).validatePacket(invalidVersionPacket);
        
        // 4. Could also craft packet to cause memory corruption
        bytes memory largePacket = new bytes(2**32); // Extremely large packet
        SimpleMessageLib(messageLib).validatePacket(largePacket);
    }
}
```

### Recommended Mitigation
1. Add comprehensive packet validation:
```solidity
// Add constants for validation
uint256 constant MIN_PACKET_SIZE = 64; // Example minimum size
uint256 constant MAX_PACKET_SIZE = 1024 * 1024; // 1MB max size
uint8 constant EXPECTED_VERSION = 1;

function validatePacket(bytes calldata packetBytes) external {
    // 1. Size validation
    require(packetBytes.length >= MIN_PACKET_SIZE, "Packet too small");
    require(packetBytes.length <= MAX_PACKET_SIZE, "Packet too large");
    
    // 2. Version validation
    require(packetBytes.version() == EXPECTED_VERSION, "Invalid version");
    
    // 3. Structure validation
    require(_isValidPacketStructure(packetBytes), "Invalid structure");
    
    // 4. Content validation
    require(_isValidPacketContent(packetBytes), "Invalid content");
    
    // Existing whitelist check
    if (whitelistCaller != address(0x0) && msg.sender != whitelistCaller) {
        revert OnlyWhitelistCaller();
    }
    
    // 5. Origin validation with additional checks
    Origin memory origin = Origin(packetBytes.srcEid(), packetBytes.sender(), packetBytes.nonce());
    require(origin.srcEid != 0, "Invalid srcEid");
    require(origin.sender != address(0), "Invalid sender");
    
    // Endpoint verification
    ILayerZeroEndpointV2(endpoint).verify(
        origin,
        packetBytes.receiverB20(),
        keccak256(packetBytes.payload())
    );
}

function _isValidPacketStructure(bytes calldata packetBytes) internal pure returns (bool) {
    // Check packet header structure
    // Check field alignments
    // Check required fields presence
    return true; // Implementation needed
}

function _isValidPacketContent(bytes calldata packetBytes) internal pure returns (bool) {
    // Validate content types
    // Check for malicious patterns
    // Validate field values
    return true; // Implementation needed
}
```

2. Add packet format versioning:
```solidity
mapping(uint8 => bool) public supportedVersions;

function setSupportedVersion(uint8 version, bool supported) external onlyOwner {
    supportedVersions[version] = supported;
    emit VersionSupportUpdated(version, supported);
}
```

3. Implement rate limiting:
```solidity
mapping(address => uint256) public lastValidationTime;
uint256 public constant VALIDATION_COOLDOWN = 1 minutes;

function validatePacket(bytes calldata packetBytes) external {
    require(block.timestamp >= lastValidationTime[msg.sender] + VALIDATION_COOLDOWN, "Too many requests");
    lastValidationTime[msg.sender] = block.timestamp;
    // Rest of validation
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [H-03] Unchecked Fee Accumulation in SendUlnBase Can Lead to Fund Loss

### Description
The `SendUlnBase.sol` contract's fee management system lacks crucial safety checks on fee accumulation. The contract accumulates fees from multiple DVNs without any upper bounds or sanity checks, which could lead to excessive fees, stuck funds, or economic attacks.

```solidity
function _assignJobs(...) internal returns (uint256 totalFee, uint256[] memory dvnFees) {
    // ... code ...
    for (uint8 i = 0; i < dvnsLength; ++i) {
        // ... code ...
        dvnFees[i] = ILayerZeroDVN(dvn).assignJob(_param, options);
        if (dvnFees[i] > 0) {
            _fees[dvn] += dvnFees[i];  // Unchecked accumulation
            totalFee += dvnFees[i];     // Unchecked total
        }
    }
}
```

Key vulnerabilities:
1. No maximum limit on individual DVN fees
2. No maximum limit on total accumulated fees
3. No validation of returned fee values
4. Potential for arithmetic overflow in fee accumulation
5. No protection against malicious DVN implementations

### Impact
- DVNs could charge arbitrarily high fees
- Total fees could silently overflow
- Users could lose funds due to excessive fees
- Malicious DVNs could manipulate fee calculations
- System could become economically unviable

### Proof of Concept
```solidity
contract MaliciousDVN is ILayerZeroDVN {
    function assignJob(AssignJobParam calldata _param, bytes calldata _options) external returns (uint256) {
        // Return maximum possible fee
        return type(uint256).max;
    }
    
    function getFee(uint32 _dstEid, uint64 _confirmations, address _sender, bytes calldata _options) external returns (uint256) {
        // Quote reasonable fee but charge maximum in assignJob
        return 0.1 ether;
    }
}

contract FeeExploit {
    function exploit(address sendUln) external {
        // 1. Deploy malicious DVN
        MaliciousDVN dvn = new MaliciousDVN();
        
        // 2. Configure ULN to use malicious DVN
        // (assuming attacker has gained configuration access)
        ISendUln(sendUln).setDVN(address(dvn));
        
        // 3. When users send messages:
        // - getFee() returns small amount (0.1 ether)
        // - assignJob() charges type(uint256).max
        // - Fee accumulation overflows
        // - User funds get stuck or lost
    }
}
```

### Recommended Mitigation
1. Implement fee limits and safety checks:
```solidity
contract SendUlnBase {
    uint256 public constant MAX_TOTAL_FEE = 1000 ether;
    uint256 public constant MAX_DVN_FEE = 100 ether;
    
    function _assignJobs(
        mapping(address => uint256) storage _fees,
        UlnConfig memory _ulnConfig,
        ILayerZeroDVN.AssignJobParam memory _param,
        bytes memory dvnOptions
    ) internal returns (uint256 totalFee, uint256[] memory dvnFees) {
        uint256 runningTotal = 0;
        
        for (uint8 i = 0; i < dvnsLength; ++i) {
            // Get DVN fee with try-catch
            try ILayerZeroDVN(dvn).assignJob(_param, options) returns (uint256 fee) {
                // Validate individual fee
                require(fee <= MAX_DVN_FEE, "DVN fee exceeds maximum");
                
                // Safe accumulation
                runningTotal += fee;
                require(runningTotal <= MAX_TOTAL_FEE, "Total fee exceeds maximum");
                
                // Update state
                if (fee > 0) {
                    _fees[dvn] += fee;
                    dvnFees[i] = fee;
                }
            } catch {
                // Handle failed DVN
                revert("DVN fee calculation failed");
            }
        }
        
        return (runningTotal, dvnFees);
    }
}
```

2. Add DVN validation:
```solidity
contract SendUlnBase {
    mapping(address => bool) public verifiedDVNs;
    
    function addVerifiedDVN(address dvn) external onlyOwner {
        require(IERC165(dvn).supportsInterface(type(ILayerZeroDVN).interfaceId), "Invalid DVN");
        verifiedDVNs[dvn] = true;
    }
    
    function _assignJobs(...) internal {
        for (uint8 i = 0; i < dvnsLength; ++i) {
            address dvn = _getDVN(i);
            require(verifiedDVNs[dvn], "Unverified DVN");
            // Rest of the function
        }
    }
}
```

3. Implement fee consistency checks:
```solidity
contract SendUlnBase {
    uint256 public constant MAX_FEE_DEVIATION = 10; // 10%
    
    function _assignJobs(...) internal {
        for (uint8 i = 0; i < dvnsLength; ++i) {
            // Get quoted fee first
            uint256 quotedFee = ILayerZeroDVN(dvn).getFee(_dstEid, _confirmations, _sender, options);
            
            // Get actual fee
            uint256 actualFee = ILayerZeroDVN(dvn).assignJob(_param, options);
            
            // Check deviation
            require(
                actualFee <= quotedFee * (100 + MAX_FEE_DEVIATION) / 100,
                "Fee deviation too high"
            );
            
            // Rest of the function
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [H-04] Storage Exhaustion Attack in ReceiveUlnBase Through Unbounded Verifications

### Description
The `ReceiveUlnBase.sol` contract's verification storage mechanism lacks limits on the number of verifications a DVN can submit. The contract uses an unbounded mapping to store verifications, which could be exploited to bloat the contract's storage and potentially make the system unusable.

```solidity
mapping(bytes32 headerHash => mapping(bytes32 payloadHash => mapping(address dvn => Verification)))
    public hashLookup;

function _verify(bytes calldata _packetHeader, bytes32 _payloadHash, uint64 _confirmations) internal {
    hashLookup[keccak256(_packetHeader)][_payloadHash][msg.sender] = Verification(true, _confirmations);
    emit PayloadVerified(msg.sender, _packetHeader, _confirmations, _payloadHash);
}
```

Key vulnerabilities:
1. No limit on verifications per DVN
2. No cleanup of old verifications
3. Storage grows unbounded
4. No rate limiting on verification submissions
5. No validation of duplicate verifications

### Impact
- Contract storage could be bloated to the point of being unusable
- Gas costs for operations would increase dramatically
- Potential denial of service through storage exhaustion
- High operational costs for legitimate users
- Potential blockchain bloat affecting node operators

### Proof of Concept
```solidity
contract StorageExhaustionAttack {
    function attack(address receiveUln) external {
        // Assuming attacker has gained DVN status
        IReceiveUln uln = IReceiveUln(receiveUln);
        
        // Generate unique packets and payloads
        for (uint i = 0; i < 1000; i++) {
            bytes memory packetHeader = _generateUniquePacket(i);
            bytes32 payloadHash = _generateUniquePayload(i);
            
            // Submit verification for each unique combination
            // Each verification adds a new storage slot
            uln.verify(packetHeader, payloadHash, 1);
        }
        
        // Result:
        // - 1000 new storage slots created
        // - No way to clean up these slots
        // - Contract storage grows linearly with attack duration
    }
    
    function calculateAttackCost(uint256 numVerifications) external pure returns (uint256) {
        // Storage slot cost = 20,000 gas
        // Each verification uses at least one slot
        return numVerifications * 20000;
    }
}

contract StorageAnalysis {
    function analyzeStorage(address receiveUln) external view returns (uint256) {
        // 1. Count total storage slots used
        uint256 totalSlots = 0;
        
        // 2. Analyze storage pattern
        assembly {
            // ... storage slot counting logic ...
        }
        
        // 3. Project growth
        // Each verification adds:
        // - 1 slot for headerHash mapping
        // - 1 slot for payloadHash mapping
        // - 1 slot for verification data
        return totalSlots * 3;
    }
}
```

### Recommended Mitigation
1. Implement verification limits and tracking:
```solidity
contract ReceiveUlnBase {
    uint256 public constant MAX_VERIFICATIONS_PER_DVN = 1000;
    uint256 public constant VERIFICATION_WINDOW = 1 days;
    
    struct DVNStats {
        uint256 verificationCount;
        uint256 windowStart;
    }
    
    mapping(address => DVNStats) public dvnStats;
    
    function _verify(bytes calldata _packetHeader, bytes32 _payloadHash, uint64 _confirmations) internal {
        // Reset window if needed
        if (block.timestamp >= dvnStats[msg.sender].windowStart + VERIFICATION_WINDOW) {
            dvnStats[msg.sender].verificationCount = 0;
            dvnStats[msg.sender].windowStart = block.timestamp;
        }
        
        // Check limits
        require(dvnStats[msg.sender].verificationCount < MAX_VERIFICATIONS_PER_DVN, "Too many verifications");
        
        // Update stats
        dvnStats[msg.sender].verificationCount++;
        
        // Store verification
        hashLookup[keccak256(_packetHeader)][_payloadHash][msg.sender] = Verification(true, _confirmations);
        emit PayloadVerified(msg.sender, _packetHeader, _confirmations, _payloadHash);
    }
}
```

2. Add storage cleanup mechanisms:
```solidity
contract ReceiveUlnBase {
    uint256 public constant MAX_VERIFICATION_AGE = 7 days;
    
    struct VerificationWithTimestamp {
        bool submitted;
        uint64 confirmations;
        uint256 timestamp;
    }
    
    mapping(bytes32 => mapping(bytes32 => mapping(address => VerificationWithTimestamp))) 
        public hashLookup;
    
    function cleanupOldVerifications(bytes32[] calldata headerHashes, bytes32[] calldata payloadHashes) external {
        for (uint i = 0; i < headerHashes.length; i++) {
            bytes32 headerHash = headerHashes[i];
            bytes32 payloadHash = payloadHashes[i];
            
            VerificationWithTimestamp storage verification = hashLookup[headerHash][payloadHash][msg.sender];
            if (verification.timestamp + MAX_VERIFICATION_AGE < block.timestamp) {
                delete hashLookup[headerHash][payloadHash][msg.sender];
                emit VerificationCleaned(headerHash, payloadHash, msg.sender);
            }
        }
    }
}
```

3. Implement verification deduplication:
```solidity
contract ReceiveUlnBase {
    mapping(bytes32 => bool) public usedVerificationHashes;
    
    function _verify(bytes calldata _packetHeader, bytes32 _payloadHash, uint64 _confirmations) internal {
        bytes32 verificationHash = keccak256(abi.encodePacked(_packetHeader, _payloadHash, msg.sender));
        require(!usedVerificationHashes[verificationHash], "Duplicate verification");
        
        usedVerificationHashes[verificationHash] = true;
        
        // Rest of verification logic
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [H-05] DVN Multi-Sig Replay Attack Vulnerability

### Description
The `DVN.sol` contract's multi-signature execution mechanism relies solely on hash tracking for replay protection, which is insufficient for cross-chain scenarios. The current implementation only checks if a hash has been used but doesn't implement proper nonce tracking or domain separation.

```solidity
function execute(ExecuteParam[] calldata _params) external onlyRole(ADMIN_ROLE) {
    for (uint256 i = 0; i < _params.length; ++i) {
        // ... validation ...
        bytes32 hash = hashCallData(param.vid, param.target, param.callData, param.expiration);
        
        // Only hash-based replay protection
        if (usedHashes[hash]) {
            emit HashAlreadyUsed(param, hash);
            continue;
        }
        usedHashes[hash] = true;
        
        (bool success, bytes memory rtnData) = param.target.call(param.callData);
        // ... error handling ...
    }
}

function hashCallData(
    uint32 _vid,
    address _target,
    bytes calldata _callData,
    uint256 _expiration
) public pure returns (bytes32) {
    return keccak256(abi.encodePacked(_vid, _target, _expiration, _callData));
}
```

Key vulnerabilities:
1. No nonce tracking per signer/chain
2. No domain separation for cross-chain replay protection
3. Hash collisions possible with carefully crafted parameters
4. Expiration timestamp is the only time-based protection
5. No validation of signature order

### Impact
- Multi-sig transactions could be replayed across different chains
- Malicious actors could reuse valid signatures
- Critical admin operations could be duplicated
- No protection against cross-chain replay attacks
- Potential for unauthorized configuration changes

### Proof of Concept
```solidity
contract DVNReplayExploit {
    function demonstrateReplay(address dvn, ExecuteParam memory param) external {
        // 1. Capture a valid multi-sig execution on chain A
        bytes32 hash = IDVN(dvn).hashCallData(
            param.vid,
            param.target,
            param.callData,
            param.expiration
        );
        
        // 2. The same execution can be replayed on chain B
        // - Same vid (DVN identifier)
        // - Same target
        // - Same callData
        // - Same expiration
        // - Same signatures
        // Will pass all checks because:
        // - usedHashes is chain-specific
        // - No chain-specific nonce
        // - No domain separation
        
        // 3. Example attack flow:
        // Chain A: Admin sets new configuration (success)
        // Chain B: Same tx replayed, changes config again (success)
        // Chain C: Same tx replayed again (success)
        // Result: Unintended configuration changes across chains
    }
    
    function craftCollision(address dvn) external {
        // 1. Find two different sets of parameters that produce the same hash
        // Due to abi.encodePacked, potential parameter stuffing:
        // hash(vid1 + target1 + expiration1 + data1) == 
        // hash(vid2 + target2 + expiration2 + data2)
        
        // 2. Use the collision to bypass replay protection
        // First execution uses params1
        // Second execution uses params2 (different but same hash)
        // Both will execute despite usedHashes check
    }
}
```

### Recommended Mitigation
1. Implement proper nonce tracking:
```solidity
contract DVN {
    struct NonceTracker {
        uint256 current;
        mapping(uint256 => bool) used;
    }
    
    // Nonce per chain per signer
    mapping(address => mapping(uint256 => NonceTracker)) public nonces;
    
    function execute(ExecuteParam[] calldata _params) external onlyRole(ADMIN_ROLE) {
        for (uint256 i = 0; i < _params.length; ++i) {
            // Track nonce per signer
            for (uint256 j = 0; j < _signers.length; j++) {
                address signer = _signers[j];
                uint256 nonce = _nonces[j];
                
                require(!nonces[signer][chainId].used[nonce], "Nonce used");
                nonces[signer][chainId].used[nonce] = true;
                
                if (nonce > nonces[signer][chainId].current) {
                    nonces[signer][chainId].current = nonce;
                }
            }
            
            // Rest of execution logic
        }
    }
}
```

2. Add domain separation:
```solidity
contract DVN {
    function hashCallData(
        uint32 _vid,
        address _target,
        bytes calldata _callData,
        uint256 _expiration
    ) public view returns (bytes32) {
        // Include chain-specific data
        bytes32 domainSeparator = keccak256(
            abi.encode(
                "DVN_DOMAIN",
                block.chainid,
                address(this)
            )
        );
        
        return keccak256(
            abi.encode(
                domainSeparator,
                _vid,
                _target,
                _expiration,
                keccak256(_callData)
            )
        );
    }
}
```

3. Implement signature ordering:
```solidity
contract DVN {
    function _validateSignatures(bytes[] memory _signatures) internal view {
        address lastSigner = address(0);
        
        for (uint256 i = 0; i < _signatures.length; i++) {
            address signer = recoverSigner(_signatures[i]);
            
            // Enforce signature ordering
            require(signer > lastSigner, "Invalid signature order");
            lastSigner = signer;
            
            require(isSigner[signer], "Invalid signer");
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [H-06] Fee Manipulation Through Block Time in DVNFeeLib

### Description
The `DVNFeeLib.sol` contract's block time validation mechanism contains critical vulnerabilities in its timestamp calculation and validation logic. The current implementation performs unbounded arithmetic operations and lacks proper validation of block time configurations, which could lead to fee manipulation and potential overflow.

```solidity
function _assertCmdTypeSupported(
    uint32 _targetEid,
    bool _isBlockNum,
    uint64 _blockNumOrTimestamp,
    uint8 _cmdType
) internal view {
    BlockTimeConfig memory blockCnf = dstBlockTimeConfigs[_targetEid];
    uint64 timestamp = _blockNumOrTimestamp;
    if (_isBlockNum) {
        // Unbounded arithmetic operations
        if (_blockNumOrTimestamp > blockCnf.blockNum) {
            timestamp = blockCnf.timestamp +
                ((_blockNumOrTimestamp - blockCnf.blockNum) * blockCnf.avgBlockTime) /
                1000;
        } else {
            timestamp = blockCnf.timestamp -
                ((blockCnf.blockNum - _blockNumOrTimestamp) * blockCnf.avgBlockTime) /
                1000;
        }
    }
    
    // Insufficient validation
    if (
        timestamp + blockCnf.maxPastRetention < block.timestamp ||
        timestamp > block.timestamp + blockCnf.maxFutureRetention
    ) {
        revert DVN_TimestampOutOfRange(_targetEid, timestamp);
    }
}
```

Key vulnerabilities:
1. Unbounded block time calculations
2. No validation of block time configuration
3. Potential for timestamp overflow
4. No maximum block time difference checks
5. No validation of retention periods

### Impact
- Fees could be manipulated through crafted block numbers
- Timestamp calculations could overflow
- Block time configurations could be set to unsafe values
- Potential for economic attacks through fee manipulation
- System could become unusable with invalid block times

### Proof of Concept
```solidity
contract BlockTimeExploit {
    function demonstrateOverflow(address dvnFeeLib) external {
        // 1. Set malicious block time config
        BlockTimeConfig memory config = BlockTimeConfig({
            avgBlockTime: type(uint32).max,  // Maximum possible block time
            blockNum: 1,
            timestamp: uint64(block.timestamp),
            maxPastRetention: type(uint32).max,
            maxFutureRetention: type(uint32).max
        });
        
        // 2. Calculate overflow
        uint64 blockNum = 2;
        // This will overflow:
        // timestamp = config.timestamp + ((blockNum - config.blockNum) * config.avgBlockTime) / 1000
        // = timestamp + (1 * type(uint32).max) / 1000
        // Result: incorrect timestamp, leading to incorrect fees
        
        // 3. Manipulate fees through block time
        function manipulateFees(address dvnFeeLib, uint32 targetEid) external {
            // 1. First set very low block time
            BlockTimeConfig memory lowConfig = BlockTimeConfig({
                avgBlockTime: 1,  // 1ms block time
                blockNum: 1,
                timestamp: uint64(block.timestamp),
                maxPastRetention: 1 days,
                maxFutureRetention: 1 days
            });
            IDVNFeeLib(dvnFeeLib).setDstBlockTimeConfigs([targetEid], [lowConfig]);
            
            // 2. Get low fee quote using recent block
            uint256 lowFee = IDVNFeeLib(dvnFeeLib).getFee(...);
            
            // 3. Switch to high block time
            BlockTimeConfig memory highConfig = BlockTimeConfig({
                avgBlockTime: type(uint32).max,
                blockNum: 1,
                timestamp: uint64(block.timestamp),
                maxPastRetention: 1 days,
                maxFutureRetention: 1 days
            });
            IDVNFeeLib(dvnFeeLib).setDstBlockTimeConfigs([targetEid], [highConfig]);
            
            // 4. Get high fee quote using same block
            uint256 highFee = IDVNFeeLib(dvnFeeLib).getFee(...);
            
            // Result: Massive fee difference for same operation
        }
    }
}
```

### Recommended Mitigation
1. Implement safe block time calculations:
```solidity
contract DVNFeeLib {
    uint256 public constant MAX_BLOCK_TIME = 1 hours;
    uint256 public constant MAX_TIME_DEVIATION = 1 days;
    uint256 public constant MAX_RETENTION_PERIOD = 7 days;
    
    function _validateBlockTimeConfig(BlockTimeConfig memory _config) internal pure {
        // Validate block time
        require(_config.avgBlockTime > 0, "Invalid block time");
        require(_config.avgBlockTime <= MAX_BLOCK_TIME, "Block time too high");
        
        // Validate retention periods
        require(_config.maxPastRetention <= MAX_RETENTION_PERIOD, "Past retention too high");
        require(_config.maxFutureRetention <= MAX_RETENTION_PERIOD, "Future retention too high");
        
        // Validate reference points
        require(_config.blockNum > 0, "Invalid block number");
        require(_config.timestamp > 0, "Invalid timestamp");
        require(_config.timestamp <= block.timestamp, "Future timestamp");
    }
    
    function _calculateTimestamp(
        BlockTimeConfig memory _config,
        uint64 _blockNum
    ) internal pure returns (uint64) {
        // Calculate block difference
        uint256 blockDiff;
        if (_blockNum > _config.blockNum) {
            blockDiff = _blockNum - _config.blockNum;
            require(blockDiff <= type(uint32).max, "Block diff too high");
            
            // Safe multiplication
            uint256 timeDiff = (blockDiff * uint256(_config.avgBlockTime)) / 1000;
            require(timeDiff <= MAX_TIME_DEVIATION, "Time diff too high");
            
            // Safe addition
            uint256 newTimestamp = _config.timestamp + timeDiff;
            require(newTimestamp <= type(uint64).max, "Timestamp overflow");
            
            return uint64(newTimestamp);
        } else {
            blockDiff = _config.blockNum - _blockNum;
            require(blockDiff <= type(uint32).max, "Block diff too high");
            
            // Safe multiplication
            uint256 timeDiff = (blockDiff * uint256(_config.avgBlockTime)) / 1000;
            require(timeDiff <= MAX_TIME_DEVIATION, "Time diff too high");
            
            // Safe subtraction
            require(timeDiff <= _config.timestamp, "Timestamp underflow");
            
            return uint64(_config.timestamp - timeDiff);
        }
    }
}
```

2. Add configuration timelock:
```solidity
contract DVNFeeLib {
    struct PendingConfig {
        BlockTimeConfig config;
        uint256 effectiveTime;
    }
    
    mapping(uint32 => PendingConfig) public pendingConfigs;
    uint256 public constant CONFIG_DELAY = 1 days;
    
    function setDstBlockTimeConfigs(
        uint32[] calldata dstEids,
        BlockTimeConfig[] calldata _blockConfigs
    ) external onlyOwner {
        for (uint256 i = 0; i < dstEids.length; i++) {
            // Validate config
            _validateBlockTimeConfig(_blockConfigs[i]);
            
            // Set pending config
            pendingConfigs[dstEids[i]] = PendingConfig({
                config: _blockConfigs[i],
                effectiveTime: block.timestamp + CONFIG_DELAY
            });
            
            emit BlockTimeConfigPending(dstEids[i], _blockConfigs[i]);
        }
    }
    
    function applyPendingConfig(uint32 _dstEid) external {
        PendingConfig storage pending = pendingConfigs[_dstEid];
        require(pending.effectiveTime > 0, "No pending config");
        require(block.timestamp >= pending.effectiveTime, "Too early");
        
        dstBlockTimeConfigs[_dstEid] = pending.config;
        delete pendingConfigs[_dstEid];
        
        emit BlockTimeConfigApplied(_dstEid, pending.config);
    }
}
```

3. Implement fee safety checks:
```solidity
contract DVNFeeLib {
    uint256 public constant MAX_FEE_MULTIPLIER = 10;
    
    function _validateFee(
        uint256 _baseFee,
        uint256 _actualFee
    ) internal pure {
        // Ensure fee hasn't grown too much due to block time
        require(_actualFee <= _baseFee * MAX_FEE_MULTIPLIER, "Fee too high");
    }
    
    function getFee(...) public view returns (uint256) {
        uint256 baseFee = _calculateBaseFee(...);
        uint256 adjustedFee = _applyBlockTimeMultiplier(baseFee, ...);
        
        _validateFee(baseFee, adjustedFee);
        return adjustedFee;
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified

## [H-07] Arbitrary Message Execution in OFT SEND_AND_CALL Operations

### Description
The `OFTCore.sol` contract implements a `SEND_AND_CALL` message type that allows arbitrary message composition without proper validation or restrictions. This functionality is exposed through the `send()` function and processed in `_lzReceive()`. The issue lies in the lack of validation on composed message content and potential for malicious cross-chain callbacks.

```solidity
function _lzReceive(
    Origin calldata _origin,
    bytes32 _guid,
    bytes calldata _message,
    address _executor,
    bytes calldata _extraData
) internal virtual override {
    address toAddress = _message.sendTo().bytes32ToAddress();
    uint256 amountReceivedLD = _credit(toAddress, _toLD(_message.amountSD()), _origin.srcEid);

    if (_message.isComposed()) {
        bytes memory composeMsg = OFTComposeMsgCodec.encode(
            _origin.nonce,
            _origin.srcEid,
            amountReceivedLD,
            _message.composeMsg()  // No validation on composed message content
        );
        endpoint.sendCompose(toAddress, _guid, 0, composeMsg);
    }
}
```

Key vulnerabilities:
1. No validation on composed message content
2. No restrictions on callback destinations
3. Potential for cross-chain reentrancy
4. No rate limiting on composed messages
5. Missing validation of callback results

### Impact
- Malicious actors could execute arbitrary code on destination chains
- Potential for cross-chain reentrancy attacks
- Risk of token theft through malicious callbacks
- Possible denial of service through message composition
- State inconsistency across chains

### Proof of Concept
```solidity
contract MaliciousOFTExploit {
    function exploit(address oft, uint32 dstEid) external {
        // 1. Create malicious composed message
        bytes memory maliciousCallback = abi.encodeWithSignature(
            "attack(address,uint256)",
            address(this),
            1000000
        );
        
        // 2. Send OFT transfer with malicious compose
        SendParam memory param = SendParam({
            dstEid: dstEid,
            to: bytes32(uint256(uint160(address(this)))),
            amountLD: 1000,  // Small amount to pass checks
            minAmountLD: 1000,
            extraOptions: "",
            composeMsg: maliciousCallback,  // Malicious callback
            oftCmd: ""
        });
        
        // 3. Execute attack
        IOFT(oft).send(param, MessagingFee(0, 0), address(this));
        
        // 4. On destination chain, malicious callback executes
        // - Can perform reentrancy
        // - Can manipulate token balances
        // - Can execute arbitrary code
    }
    
    // Malicious callback function on destination chain
    function attack(address target, uint256 amount) external {
        // Perform malicious actions
        // - Drain tokens
        // - Manipulate state
        // - Trigger more cross-chain messages
    }
}
```

### Recommended Mitigation
1. Implement strict message validation:
```solidity
contract OFTCore {
    // Whitelist of allowed compose message targets
    mapping(address => bool) public allowedComposeTargets;
    
    function _lzReceive(...) internal virtual override {
        // ... existing code ...
        
        if (_message.isComposed()) {
            // Validate compose message target
            address target = _decodeComposeTarget(_message.composeMsg());
            require(allowedComposeTargets[target], "Invalid compose target");
            
            // Validate compose message content
            require(_isValidComposeMsg(_message.composeMsg()), "Invalid compose msg");
            
            // Rate limit checks
            require(_isWithinRateLimit(target), "Rate limit exceeded");
            
            bytes memory composeMsg = OFTComposeMsgCodec.encode(...);
            endpoint.sendCompose(toAddress, _guid, 0, composeMsg);
            
            // Track compose message execution
            _trackComposeExecution(target);
        }
    }
    
    function _isValidComposeMsg(bytes memory _msg) internal view returns (bool) {
        // Implement validation logic
        // - Check message format
        // - Validate function signatures
        // - Check parameter bounds
        return true;
    }
    
    function _isWithinRateLimit(address _target) internal view returns (bool) {
        // Implement rate limiting
        return true;
    }
}
```

2. Add cross-chain reentrancy protection:
```solidity
contract OFTCore {
    // Track cross-chain message execution state
    mapping(bytes32 => bool) public executingMessages;
    
    modifier nonReentrant(bytes32 _guid) {
        require(!executingMessages[_guid], "Reentrant call");
        executingMessages[_guid] = true;
        _;
        executingMessages[_guid] = false;
    }
    
    function _lzReceive(
        Origin calldata _origin,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) internal virtual override nonReentrant(_guid) {
        // ... rest of the function
    }
}
```

3. Implement callback result validation:
```solidity
contract OFTCore {
    function _lzReceive(...) internal virtual override {
        // ... existing code ...
        
        if (_message.isComposed()) {
            // ... validation checks ...
            
            // Execute compose with result validation
            bool success;
            bytes memory result;
            (success, result) = endpoint.sendCompose(toAddress, _guid, 0, composeMsg);
            
            // Validate execution result
            require(success, "Compose execution failed");
            require(_isValidResult(result), "Invalid compose result");
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified

## [H-08] OFTAdapter Incompatibility with Non-Standard Tokens Can Lead to Fund Loss

### Description
The `OFTAdapter.sol` contract's implementation assumes standard ERC20 token behavior but lacks proper validation and handling of non-standard tokens (fee-on-transfer, rebasing, etc.). This assumption could lead to significant fund loss when used with such tokens.

```solidity
function _debit(
    address _from,
    uint256 _amountLD,
    uint256 _minAmountLD,
    uint32 _dstEid
) internal virtual override returns (uint256 amountSentLD, uint256 amountReceivedLD) {
    (amountSentLD, amountReceivedLD) = _debitView(_amountLD, _minAmountLD, _dstEid);
    // No pre/post balance check
    innerToken.safeTransferFrom(_from, address(this), amountSentLD);
    // Actual received amount could be different
}

function _credit(
    address _to,
    uint256 _amountLD,
    uint32 /*_srcEid*/
) internal virtual override returns (uint256 amountReceivedLD) {
    // No balance verification
    innerToken.safeTransfer(_to, _amountLD);
    // Assumes 1:1 transfer ratio
    return _amountLD;
}
```

Key vulnerabilities:
1. No validation of token behavior during initialization
2. Missing pre/post balance checks for transfers
3. Incorrect amount tracking with fee-on-transfer tokens
4. No handling of rebasing token balance changes
5. No protection against deflationary tokens

### Impact
- Loss of funds when used with fee-on-transfer tokens
- Incorrect balance tracking across chains
- Potential for double-spending with rebasing tokens
- System-wide supply inconsistencies
- Permanent loss of user funds

### Proof of Concept
```solidity
contract FeeToken is IERC20 {
    uint256 public constant FEE_PERCENT = 5;
    
    function transfer(address to, uint256 amount) external returns (bool) {
        uint256 fee = (amount * FEE_PERCENT) / 100;
        uint256 actualAmount = amount - fee;
        // Transfer actualAmount instead of full amount
        _transfer(msg.sender, to, actualAmount);
        return true;
    }
}

contract OFTAdapterExploit {
    function demonstrateLoss(address adapter, address feeToken) external {
        // 1. Deploy fee token
        FeeToken token = FeeToken(feeToken);
        
        // 2. Setup cross-chain transfer
        uint256 amount = 1000e18;
        SendParam memory param = SendParam({
            dstEid: 2,
            to: bytes32(uint256(uint160(address(this)))),
            amountLD: amount,
            minAmountLD: amount,  // Expects full amount
            extraOptions: "",
            composeMsg: "",
            oftCmd: ""
        });
        
        // 3. Execute transfer
        // User sends: 1000 tokens
        // Adapter receives: 950 tokens (5% fee)
        // But records: 1000 tokens locked
        // Result: 50 tokens permanently lost
        IOFTAdapter(adapter).send(param, MessagingFee(0, 0), address(this));
        
        // 4. On destination chain
        // Adapter tries to send: 1000 tokens
        // Actually sends: 950 tokens
        // Records: 1000 tokens received
        // Result: Accounting mismatch and lost funds
    }
}

contract RebasingTokenExploit {
    function demonstrateRebaseLoss(address adapter) external {
        // 1. Initial state
        // User deposits 1000 tokens
        // Adapter records 1000 tokens locked
        
        // 2. Token rebases down 50%
        // Actual balance: 500 tokens
        // Recorded balance: Still 1000 tokens
        
        // 3. Another user withdraws
        // Tries to withdraw 1000 tokens
        // Only 500 tokens available
        // Transaction fails or partial withdrawal
        // Result: Funds stuck or lost
    }
}
```

### Recommended Mitigation
1. Implement token behavior detection:
```solidity
contract OFTAdapter {
    error UnsupportedToken();
    error TransferFailed();
    
    bool public immutable hasTransferFee;
    bool public immutable isRebasable;
    
    constructor(address _token, ...) {
        // Detect token behavior
        hasTransferFee = _detectTransferFee(_token);
        isRebasable = _detectRebasable(_token);
        
        // Only allow standard tokens
        if (hasTransferFee || isRebasable) {
            revert UnsupportedToken();
        }
        
        // Initialize adapter
        innerToken = IERC20(_token);
    }
    
    function _detectTransferFee(address _token) internal returns (bool) {
        IERC20 token = IERC20(_token);
        uint256 testAmount = 1000;
        
        // Fund contract for test
        token.transferFrom(msg.sender, address(this), testAmount);
        
        // Test transfer
        uint256 balanceBefore = token.balanceOf(address(this));
        token.transfer(msg.sender, testAmount);
        uint256 balanceAfter = token.balanceOf(address(this));
        
        // Check if full amount was transferred
        return balanceAfter != balanceBefore - testAmount;
    }
    
    function _detectRebasable(address _token) internal returns (bool) {
        // Implementation specific to detecting rebase behavior
        // Could involve multiple balance checks over time
        // Or checking for known rebasing token interfaces
        return false;
    }
}
```

2. Add balance verification:
```solidity
contract OFTAdapter {
    struct BalanceSnapshot {
        uint256 recorded;
        uint256 actual;
        uint256 timestamp;
    }
    
    mapping(uint32 => BalanceSnapshot) public chainBalances;
    
    function _debit(
        address _from,
        uint256 _amountLD,
        uint256 _minAmountLD,
        uint32 _dstEid
    ) internal virtual override returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        // Take balance snapshot
        uint256 balanceBefore = innerToken.balanceOf(address(this));
        
        // Execute transfer
        innerToken.safeTransferFrom(_from, address(this), _amountLD);
        
        // Verify actual amount received
        uint256 balanceAfter = innerToken.balanceOf(address(this));
        uint256 actualAmount = balanceAfter - balanceBefore;
        
        // Verify minimum amount
        require(actualAmount >= _minAmountLD, "Transfer amount too low");
        
        // Update balance tracking
        chainBalances[_dstEid] = BalanceSnapshot({
            recorded: _amountLD,
            actual: actualAmount,
            timestamp: block.timestamp
        });
        
        return (actualAmount, actualAmount);
    }
}
```

3. Implement balance reconciliation:
```solidity
contract OFTAdapter {
    struct GlobalSupply {
        uint256 totalLocked;
        uint256 totalMinted;
        uint256 lastReconciliation;
    }
    
    GlobalSupply public globalSupply;
    uint256 public constant RECONCILIATION_INTERVAL = 1 days;
    
    function reconcileSupply(uint32[] calldata chainIds) external {
        require(
            block.timestamp >= globalSupply.lastReconciliation + RECONCILIATION_INTERVAL,
            "Too soon"
        );
        
        uint256 totalLocked;
        uint256 totalMinted;
        
        // Calculate totals
        for (uint32 chainId : chainIds) {
            SupplyState storage state = chainSupply[chainId];
            totalLocked += state.lockedAmount;
            totalMinted += state.mintedAmount;
        }
        
        // Validate supply consistency
        require(totalLocked == totalMinted, "Supply mismatch");
        require(totalLocked <= maxGlobalSupply, "Supply exceeded");
        
        // Update global state
        globalSupply = GlobalSupply({
            totalLocked: totalLocked,
            totalMinted: totalMinted,
            lastReconciliation: block.timestamp
        });
        
        emit SupplyReconciled(totalLocked, totalMinted);
    }
}
```

4. Implement supply verification:
```solidity
contract OFTAdapter {
    function verifySupply(uint32 chainId) external view returns (bool) {
        SupplyState storage state = chainSupply[chainId];
        
        // Verify local balance
        uint256 actualBalance = innerToken.balanceOf(address(this));
        if (chainId == block.chainid) {
            // Source chain should match locked amount
            return actualBalance == state.lockedAmount;
        } else {
            // Destination chain should match minted amount
            return actualBalance == state.mintedAmount;
        }
    }
    
    function _beforeTransfer(uint32 _dstEid, uint256 _amount) internal view {
        // Pre-transfer supply checks
        require(verifySupply(block.chainid), "Local supply mismatch");
        require(
            chainSupply[_dstEid].mintedAmount + _amount <= maxGlobalSupply,
            "Would exceed supply"
        );
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified

## [H-09] OFTAdapter Cross-Chain Supply Inconsistency Can Lead to Token Inflation

### Description
The `OFTAdapter.sol` contract lacks proper cross-chain supply tracking and synchronization mechanisms. The current implementation does not maintain or validate global token supply across chains, which could lead to token inflation, double-spending, or permanent supply inconsistencies.

```solidity
contract OFTAdapter is OFTCore {
    IERC20 internal immutable innerToken;
    
    function _debit(address _from, uint256 _amountLD, ...) internal virtual override {
        // No cross-chain supply tracking
        innerToken.safeTransferFrom(_from, address(this), amountSentLD);
    }
    
    function _credit(address _to, uint256 _amountLD, ...) internal virtual override {
        // No supply validation
        innerToken.safeTransfer(_to, _amountLD);
        return _amountLD;
    }
}
```

Key vulnerabilities:
1. No global supply tracking across chains
2. Missing supply validation on transfers
3. No mechanism to detect supply inconsistencies
4. Lack of supply reconciliation functionality
5. No maximum supply enforcement

### Impact
- Token supply could become inflated across chains
- Double-spending through cross-chain transfers
- Permanent loss of supply consistency
- Economic damage to token value
- System-wide accounting failures

### Proof of Concept
```solidity
contract SupplyExploit {
    function demonstrateInflation(address adapter, uint32[] calldata chainIds) external {
        // 1. Initial state
        // Chain A: 1000 tokens locked
        // Chain B: 0 tokens
        // Chain C: 0 tokens
        // Total supply: 1000 tokens
        
        // 2. Exploit through parallel transfers
        for (uint32 chainId : chainIds) {
            // Send to each chain in parallel
            SendParam memory param = SendParam({
                dstEid: chainId,
                to: bytes32(uint256(uint160(address(this)))),
                amountLD: 1000,
                minAmountLD: 1000,
                extraOptions: "",
                composeMsg: "",
                oftCmd: ""
            });
            
            // Each transfer appears valid in isolation
            IOFTAdapter(adapter).send(param, MessagingFee(0, 0), address(this));
        }
        
        // 3. Result
        // Chain A: 1000 tokens locked
        // Chain B: 1000 tokens received
        // Chain C: 1000 tokens received
        // Total supply: 3000 tokens (inflated)
    }
    
    function demonstrateDoubleSpend(address adapter) external {
        // 1. Send tokens to Chain B
        SendParam memory param1 = SendParam({
            dstEid: CHAIN_B,
            to: bytes32(uint256(uint160(address(this)))),
            amountLD: 1000,
            minAmountLD: 1000,
            extraOptions: "",
            composeMsg: "",
            oftCmd: ""
        });
        
        // First transfer locks tokens
        IOFTAdapter(adapter).send(param1, MessagingFee(0, 0), address(this));
        
        // 2. Before Chain B confirms, send to Chain C
        SendParam memory param2 = param1;
        param2.dstEid = CHAIN_C;
        
        // Second transfer uses same tokens
        IOFTAdapter(adapter).send(param2, MessagingFee(0, 0), address(this));
        
        // Result: Same tokens spent twice
    }
}
```

### Recommended Mitigation
1. Implement global supply tracking:
```solidity
contract OFTAdapter {
    struct SupplyState {
        uint256 lockedAmount;
        uint256 mintedAmount;
        uint256 lastUpdate;
    }
    
    mapping(uint32 => SupplyState) public chainSupply;
    uint256 public immutable maxGlobalSupply;
    
    event SupplyUpdated(uint32 chainId, uint256 locked, uint256 minted);
    
    function _debit(
        address _from,
        uint256 _amountLD,
        uint256 _minAmountLD,
        uint32 _dstEid
    ) internal virtual override returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        // Update source chain supply
        chainSupply[block.chainid].lockedAmount += _amountLD;
        require(chainSupply[block.chainid].lockedAmount <= maxGlobalSupply, "Exceeds max supply");
        
        // Execute transfer
        innerToken.safeTransferFrom(_from, address(this), _amountLD);
        
        emit SupplyUpdated(block.chainid, chainSupply[block.chainid].lockedAmount, 0);
        return (_amountLD, _amountLD);
    }
    
    function _credit(
        address _to,
        uint256 _amountLD,
        uint32 _srcEid
    ) internal virtual override returns (uint256) {
        // Update destination chain supply
        chainSupply[block.chainid].mintedAmount += _amountLD;
        require(chainSupply[block.chainid].mintedAmount <= maxGlobalSupply, "Exceeds max supply");
        
        // Execute transfer
        innerToken.safeTransfer(_to, _amountLD);
        
        emit SupplyUpdated(block.chainid, 0, chainSupply[block.chainid].mintedAmount);
        return _amountLD;
    }
}
```

2. Add supply reconciliation:
```solidity
contract OFTAdapter {
    struct GlobalSupply {
        uint256 totalLocked;
        uint256 totalMinted;
        uint256 lastReconciliation;
    }
    
    GlobalSupply public globalSupply;
    uint256 public constant RECONCILIATION_INTERVAL = 1 days;
    
    function reconcileSupply(uint32[] calldata chainIds) external {
        require(
            block.timestamp >= globalSupply.lastReconciliation + RECONCILIATION_INTERVAL,
            "Too soon"
        );
        
        uint256 totalLocked;
        uint256 totalMinted;
        
        // Calculate totals
        for (uint32 chainId : chainIds) {
            SupplyState storage state = chainSupply[chainId];
            totalLocked += state.lockedAmount;
            totalMinted += state.mintedAmount;
        }
        
        // Validate supply consistency
        require(totalLocked == totalMinted, "Supply mismatch");
        require(totalLocked <= maxGlobalSupply, "Supply exceeded");
        
        // Update global state
        globalSupply = GlobalSupply({
            totalLocked: totalLocked,
            totalMinted: totalMinted,
            lastReconciliation: block.timestamp
        });
        
        emit SupplyReconciled(totalLocked, totalMinted);
    }
}
```

3. Implement supply verification:
```solidity
contract OFTAdapter {
    function verifySupply(uint32 chainId) external view returns (bool) {
        SupplyState storage state = chainSupply[chainId];
        
        // Verify local balance
        uint256 actualBalance = innerToken.balanceOf(address(this));
        if (chainId == block.chainid) {
            // Source chain should match locked amount
            return actualBalance == state.lockedAmount;
        } else {
            // Destination chain should match minted amount
            return actualBalance == state.mintedAmount;
        }
    }
    
    function _beforeTransfer(uint32 _dstEid, uint256 _amount) internal view {
        // Pre-transfer supply checks
        require(verifySupply(block.chainid), "Local supply mismatch");
        require(
            chainSupply[_dstEid].mintedAmount + _amount <= maxGlobalSupply,
            "Would exceed supply"
        );
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified

## [H-10] Treasury and Executor Privilege Escalation and Fund Management Vulnerabilities

### Description
The `Treasury.sol` and `Executor.sol` contracts contain critical vulnerabilities related to privileged operations and fund management:

1. In `Treasury.sol`:
```solidity
function withdrawToken(address _token, address _to, uint256 _amount) external onlyOwner {
    // transfers native if _token is address(0x0)
    Transfer.nativeOrToken(_token, _to, _amount);
}

function _getFee(uint256 _totalFee, bool _payInLzToken) internal view returns (uint256) {
    if (_payInLzToken) {
        if (!lzTokenEnabled) revert LZ_Treasury_LzTokenNotEnabled();
        return lzTokenFee;
    } else {
        return (_totalFee * nativeBP) / 10000;
    }
}
```
- Single owner can withdraw all funds
- No withdrawal limits or timelock
- Fee calculations lack validation

2. In `Executor.sol`:
```solidity
function execute302(ExecutionParams calldata _executionParams) external payable onlyRole(ADMIN_ROLE) nonReentrant {
    try
        ILayerZeroEndpointV2(endpoint).lzReceive{ value: msg.value, gas: _executionParams.gasLimit }(
            _executionParams.origin,
            _executionParams.receiver,
            _executionParams.guid,
            _executionParams.message,
            _executionParams.extraData
        )
    {
        // do nothing
    } catch (bytes memory reason) {
        // Alert handling lacks validation
    }
}
```
- Privileged execution without proper validation
- Insufficient gas management
- Weak error handling

### Impact
- Potential for unauthorized fund withdrawal
- Risk of fee manipulation
- Message execution could be manipulated
- Possible DoS through gas exhaustion
- Economic attacks through fee calculations

### Proof of Concept
```solidity
contract TreasuryExploit {
    function demonstrateIssues(address treasury, address executor) external {
        Treasury t = Treasury(treasury);
        Executor e = Executor(executor);
        
        // 1. Fee manipulation
        // Owner can set arbitrary fees
        if (t.owner() == address(this)) {
            t.setNativeFeeBP(10000); // 100% fee
            t.setLzTokenFee(type(uint256).max);
        }
        
        // 2. Withdrawal attack
        // Owner can drain all funds instantly
        if (t.owner() == address(this)) {
            address[] memory tokens = getTokenList();
            for (uint i = 0; i < tokens.length; i++) {
                uint256 balance = IERC20(tokens[i]).balanceOf(address(t));
                t.withdrawToken(tokens[i], address(this), balance);
            }
        }
        
        // 3. Execution manipulation
        // Admin can manipulate message execution
        if (e.hasRole(e.ADMIN_ROLE(), address(this))) {
            // Can grant MESSAGE_LIB_ROLE to malicious contracts
            w.grantRole(w.MESSAGE_LIB_ROLE(), address(this));
            // Can withdraw all tokens
            w.withdrawToken(address(0), address(this), type(uint256).max);
        }
    }
}
```

### Recommended Mitigation
1. Implement withdrawal safety:
```solidity
contract Treasury {
    struct WithdrawalRequest {
        address token;
        address to;
        uint256 amount;
        uint256 timestamp;
        bool executed;
    }
    
    uint256 public constant WITHDRAWAL_DELAY = 3 days;
    uint256 public constant MAX_WITHDRAWAL_PERCENT = 50; // 50%
    
    mapping(uint256 => WithdrawalRequest) public withdrawalRequests;
    uint256 public nextWithdrawalId;
    
    function requestWithdrawal(
        address _token,
        address _to,
        uint256 _amount
    ) external onlyOwner returns (uint256 withdrawalId) {
        // Check withdrawal limits
        uint256 balance = _token == address(0) 
            ? address(this).balance 
            : IERC20(_token).balanceOf(address(this));
        require(_amount <= (balance * MAX_WITHDRAWAL_PERCENT) / 100, "Exceeds limit");
        
        // Create request
        withdrawalId = nextWithdrawalId++;
        withdrawalRequests[withdrawalId] = WithdrawalRequest({
            token: _token,
            to: _to,
            amount: _amount,
            timestamp: block.timestamp,
            executed: false
        });
        
        emit WithdrawalRequested(withdrawalId, _token, _to, _amount);
    }
    
    function executeWithdrawal(uint256 _withdrawalId) external {
        WithdrawalRequest storage request = withdrawalRequests[_withdrawalId];
        require(!request.executed, "Already executed");
        require(
            block.timestamp >= request.timestamp + WITHDRAWAL_DELAY,
            "Too early"
        );
        
        request.executed = true;
        Transfer.nativeOrToken(request.token, request.to, request.amount);
        
        emit WithdrawalExecuted(_withdrawalId);
    }
}
```

2. Enhance fee management:
```solidity
contract Treasury {
    uint256 public constant MAX_FEE_BPS = 1000; // 10%
    uint256 public constant MAX_FEE_CHANGE = 100; // 1%
    uint256 public constant FEE_CHANGE_INTERVAL = 1 days;
    
    struct FeeConfig {
        uint256 nativeBP;
        uint256 lzTokenFee;
        uint256 lastUpdate;
    }
    
    FeeConfig public feeConfig;
    
    function setFees(uint256 _nativeBP, uint256 _lzTokenFee) external onlyOwner {
        require(_nativeBP <= MAX_FEE_BPS, "Fee too high");
        require(
            block.timestamp >= feeConfig.lastUpdate + FEE_CHANGE_INTERVAL,
            "Too soon"
        );
        
        // Check max change
        uint256 nativeChange = _nativeBP > feeConfig.nativeBP
            ? _nativeBP - feeConfig.nativeBP
            : feeConfig.nativeBP - _nativeBP;
        require(nativeChange <= MAX_FEE_CHANGE, "Change too high");
        
        feeConfig.nativeBP = _nativeBP;
        feeConfig.lzTokenFee = _lzTokenFee;
        feeConfig.lastUpdate = block.timestamp;
        
        emit FeesUpdated(_nativeBP, _lzTokenFee);
    }
}
```

3. Improve execution safety:
```solidity
contract Executor {
    uint256 public constant MIN_GAS_LIMIT = 100000;
    uint256 public constant MAX_GAS_LIMIT = 2000000;
    
    mapping(bytes32 => bool) public executedMessages;
    
    function execute302(
        ExecutionParams calldata _executionParams
    ) external payable onlyRole(ADMIN_ROLE) nonReentrant {
        // Validate gas limit
        require(
            _executionParams.gasLimit >= MIN_GAS_LIMIT &&
            _executionParams.gasLimit <= MAX_GAS_LIMIT,
            "Invalid gas limit"
        );
        
        // Check for duplicate execution
        bytes32 messageHash = keccak256(abi.encode(
            _executionParams.origin,
            _executionParams.receiver,
            _executionParams.guid
        ));
        require(!executedMessages[messageHash], "Already executed");
        
        // Mark as executed before call
        executedMessages[messageHash] = true;
        
        // Execute with proper error handling
        try
            ILayerZeroEndpointV2(endpoint).lzReceive{
                value: msg.value,
                gas: _executionParams.gasLimit
            }(
                _executionParams.origin,
                _executionParams.receiver,
                _executionParams.guid,
                _executionParams.message,
                _executionParams.extraData
            )
        {
            emit MessageExecuted(messageHash, true);
        } catch (bytes memory reason) {
            // Proper error handling
            emit MessageExecuted(messageHash, false);
            ILayerZeroEndpointV2(endpoint).lzReceiveAlert(
                _executionParams.origin,
                _executionParams.receiver,
                _executionParams.guid,
                _executionParams.gasLimit,
                msg.value,
                _executionParams.message,
                _executionParams.extraData,
                reason
            );
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified

## [H-11] Worker and Fee Library Vulnerabilities in Access Control and Fee Calculations

### Description
The `Worker.sol` and `ExecutorFeeLib.sol` contracts contain critical vulnerabilities in their access control and fee calculation mechanisms:

1. In `Worker.sol`:
```solidity
function hasAcl(address _sender) public view returns (bool) {
    if (hasRole(DENYLIST, _sender)) {
        return false;
    } else if (allowlistSize == 0 || hasRole(ALLOWLIST, _sender)) {
        return true;
    } else {
        return false;
    }
}

function withdrawToken(address _token, address _to, uint256 _amount) external onlyRole(ADMIN_ROLE) {
    // transfers native if _token is address(0x0)
    Transfer.nativeOrToken(_token, _to, _amount);
}
```
- ACL bypass through allowlistSize manipulation
- Unrestricted token withdrawals by admins
- No validation of role assignments

2. In `ExecutorFeeLib.sol`:
```solidity
function _applyPremiumToGas(
    uint256 _fee,
    uint16 _multiplierBps,
    uint128 _marginUSD,
    uint128 _nativePriceUSD
) internal view returns (uint256) {
    uint256 feeWithMultiplier = (_fee * _multiplierBps) / 10000;

    if (_nativePriceUSD == 0 || _marginUSD == 0) {
        return feeWithMultiplier;
    }
    uint256 feeWithMargin = (_marginUSD * nativeDecimalsRate) / _nativePriceUSD + _fee;
    return feeWithMargin > feeWithMultiplier ? feeWithMargin : feeWithMultiplier;
}

function _convertAndApplyPremiumToValue(
    uint256 _value,
    uint128 _ratio,
    uint128 _denom,
    uint16 _multiplierBps
) internal pure returns (uint256 fee) {
    if (_value > 0) {
        fee = (((_value * _ratio) / _denom) * _multiplierBps) / 10000;
    }
}
```
- Potential fee manipulation through price feed
- Rounding errors in fee calculations
- No validation of fee parameters
- Possible overflow in fee calculations

### Impact
- Unauthorized access to privileged functions
- Potential theft of funds through fee manipulation
- Economic attacks through price feed manipulation
- Denial of service through fee calculation exploits

### Proof of Concept
```solidity
contract WorkerExploit {
    function demonstrateIssues(address worker, address feeLib) external {
        Worker w = Worker(worker);
        ExecutorFeeLib f = ExecutorFeeLib(feeLib);
        
        // 1. ACL bypass
        // Empty allowlist allows everyone
        if (w.allowlistSize() == 0) {
            // Can access restricted functions
            assert(w.hasAcl(address(this)));
        }
        
        // 2. Fee manipulation
        // Manipulate price feed to maximize fees
        if (f.owner() == address(this)) {
            // Set malicious prices
            UpdatePrice[] memory updates = new UpdatePrice[](1);
            updates[0] = UpdatePrice({
                eid: 1,
                price: Price({
                    priceRatio: type(uint128).max,
                    gasPriceInUnit: type(uint64).max,
                    gasPerByte: type(uint32).max
                })
            });
            f.setDstBlockTimeConfigs([1], updates);
        }
        
        // 3. Role manipulation
        // Admin can grant roles without restrictions
        if (w.hasRole(w.DEFAULT_ADMIN_ROLE(), address(this))) {
            // Can grant MESSAGE_LIB_ROLE to malicious contracts
            w.grantRole(w.MESSAGE_LIB_ROLE(), address(this));
            // Can withdraw all tokens
            w.withdrawToken(address(0), address(this), type(uint256).max);
        }
    }
}

contract MaliciousPriceFeed {
    function estimateFeeByEid(
        uint32 _dstEid,
        uint256 _callDataSize,
        uint256 _gas
    ) external pure returns (
        uint256 totalGasFee,
        uint128 priceRatio,
        uint128 priceRatioDenominator,
        uint128 nativePriceUSD
    ) {
        // Return manipulated values to maximize fees
        return (
            type(uint256).max / 2, // Just under overflow
            type(uint128).max,
            1,
            1 // Minimize native price to maximize fee
        );
    }
}
```

### Recommended Mitigation
1. Enhance access control:
```solidity
contract Worker {
    uint256 public constant MAX_ADMINS = 5;
    uint256 public constant ROLE_TIMEOUT = 7 days;
    
    struct RoleAssignment {
        uint256 expiry;
        bool active;
    }
    
    mapping(bytes32 => mapping(address => RoleAssignment)) public roleAssignments;
    mapping(bytes32 => uint256) public roleCount;
    
    function grantRole(bytes32 _role, address _account) public override onlyRole(DEFAULT_ADMIN_ROLE) {
        require(roleCount[_role] < MAX_ADMINS, "Too many admins");
        require(_account != address(0), "Invalid address");
        
        if (!hasRole(_role, _account)) {
            roleCount[_role]++;
        }
        
        roleAssignments[_role][_account] = RoleAssignment({
            expiry: block.timestamp + ROLE_TIMEOUT,
            active: true
        });
        
        emit RoleGranted(_role, _account, msg.sender);
    }
    
    function hasRole(bytes32 _role, address _account) public view override returns (bool) {
        RoleAssignment memory assignment = roleAssignments[_role][_account];
        return assignment.active && block.timestamp < assignment.expiry;
    }
    
    function revokeRole(bytes32 _role, address _account) public override onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_account != address(0), "Invalid address");
        
        if (hasRole(_role, _account)) {
            roleCount[_role]--;
        }
        
        delete roleAssignments[_role][_account];
        
        emit RoleRevoked(_role, _account, msg.sender);
    }
}
```

2. Improve fee calculations:
```solidity
contract ExecutorFeeLib {
    uint256 public constant MAX_MULTIPLIER_BPS = 20000; // 200%
    uint256 public constant MIN_NATIVE_PRICE_USD = 1e6; // $1
    uint256 public constant MAX_FEE = 1000 ether;
    
    function _applyPremiumToGas(
        uint256 _fee,
        uint16 _multiplierBps,
        uint128 _marginUSD,
        uint128 _nativePriceUSD
    ) internal view returns (uint256) {
        require(_multiplierBps <= MAX_MULTIPLIER_BPS, "Multiplier too high");
        require(_nativePriceUSD >= MIN_NATIVE_PRICE_USD, "Price too low");
        
        uint256 feeWithMultiplier = (_fee * _multiplierBps) / 10000;
        require(feeWithMultiplier <= MAX_FEE, "Fee too high");
        
        if (_marginUSD == 0) {
            return feeWithMultiplier;
        }
        
        uint256 feeWithMargin = (_marginUSD * nativeDecimalsRate) / _nativePriceUSD + _fee;
        require(feeWithMargin <= MAX_FEE, "Margin fee too high");
        
        return feeWithMargin > feeWithMultiplier ? feeWithMargin : feeWithMultiplier;
    }
    
    function _convertAndApplyPremiumToValue(
        uint256 _value,
        uint128 _ratio,
        uint128 _denom,
        uint16 _multiplierBps
    ) internal pure returns (uint256 fee) {
        require(_denom > 0, "Invalid denominator");
        require(_multiplierBps <= MAX_MULTIPLIER_BPS, "Multiplier too high");
        
        if (_value > 0) {
            uint256 baseValue = (_value * _ratio) / _denom;
            require(baseValue <= type(uint256).max / _multiplierBps, "Value overflow");
            
            fee = (baseValue * _multiplierBps) / 10000;
            require(fee <= MAX_FEE, "Fee too high");
        }
    }
}
```

3. Add price feed validation:
```solidity
contract ExecutorFeeLib {
    struct PriceValidation {
        uint256 lastUpdate;
        uint256 minPrice;
        uint256 maxPrice;
        uint256 maxChange;
    }
    
    mapping(uint32 => PriceValidation) public priceValidation;
    
    function validateAndUpdatePrice(
        uint32 _eid,
        uint256 _price
    ) internal {
        PriceValidation storage validation = priceValidation[_eid];
        
        // Check price bounds
        require(_price >= validation.minPrice, "Price too low");
        require(_price <= validation.maxPrice, "Price too high");
        
        // Check max price change
        if (validation.lastUpdate > 0) {
            uint256 prevPrice = validation.lastUpdate;
            uint256 change = _price > prevPrice ? 
                _price - prevPrice : 
                prevPrice - _price;
                
            require(change <= validation.maxChange, "Price change too high");
        }
        
        validation.lastUpdate = _price;
    }
}
```

4. Improve model selection:
```solidity
contract ExecutorFeeLib {
    struct ChainConfig {
        ModelType modelType;
        bool active;
        uint256 lastUpdate;
    }
    
    mapping(uint32 => ChainConfig) public chainConfigs;
    
    function setChainConfig(
        uint32 _eid,
        ModelType _modelType,
        bool _active
    ) external onlyOwner {
        require(_modelType <= ModelType.OP_STACK, "Invalid model");
        
        chainConfigs[_eid] = ChainConfig({
            modelType: _modelType,
            active: _active,
            lastUpdate: block.timestamp
        });
        
        emit ChainConfigUpdated(_eid, _modelType, _active);
    }
    
    function estimateFeeByChain(
        uint32 _dstEid,
        uint256 _callDataSize,
        uint256 _gas
    ) external view returns (uint256 fee, uint128 priceRatio) {
        ChainConfig memory config = chainConfigs[_dstEid];
        require(config.active, "Chain not supported");
        
        if (config.modelType == ModelType.OP_STACK) {
            return _estimateFeeWithOptimismModel(_dstEid, _callDataSize, _gas);
        } else if (config.modelType == ModelType.ARB_STACK) {
            return _estimateFeeWithArbitrumModel(_dstEid, _callDataSize, _gas);
        } else {
            return _estimateFeeWithDefaultModel(_dstEid, _callDataSize, _gas);
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified

## [H-12] Price Feed Manipulation and Fee Calculation Vulnerabilities

### Description
The `PriceFeed.sol` contract contains critical vulnerabilities in its price feed and fee calculation mechanisms:

1. Price Update Mechanism:
```solidity
function setPrice(UpdatePrice[] calldata _price) external onlyPriceUpdater {
    for (uint256 i = 0; i < _price.length; i++) {
        UpdatePrice calldata _update = _price[i];
        _setPrice(_update.eid, _update.price);
    }
}

function setPriceForArbitrum(UpdatePriceExt calldata _update) external onlyPriceUpdater {
    _setPrice(_update.eid, _update.price);
    _arbitrumPriceExt.gasPerL2Tx = _update.extend.gasPerL2Tx;
    _arbitrumPriceExt.gasPerL1CallDataByte = _update.extend.gasPerL1CallDataByte;
}
```
- No validation of price updates
- No delay or timelock for price changes
- Single point of failure with price updater

2. Fee Calculation:
```solidity
function _estimateFeeWithDefaultModel(
    uint32 _dstEid,
    uint256 _callDataSize,
    uint256 _gas
) internal view returns (uint256 fee, uint128 priceRatio) {
    Price storage remotePrice = _defaultModelPrice[_dstEid];
    uint256 gasForCallData = _callDataSize * remotePrice.gasPerByte;
    uint256 remoteFee = (gasForCallData + _gas) * remotePrice.gasPriceInUnit;
    return ((remoteFee * remotePrice.priceRatio) / PRICE_RATIO_DENOMINATOR, remotePrice.priceRatio);
}
```
- Potential overflow in fee calculations
- No bounds checking on input parameters
- Rounding errors in price ratio calculations

3. Model Selection:
```solidity
function estimateFeeByChain(
    uint16 _dstEid,
    uint256 _callDataSize,
    uint256 _gas
) external view returns (uint256 fee, uint128 priceRatio) {
    if (_dstEid == 110 || _dstEid == 10143 || _dstEid == 20143) {
        return _estimateFeeWithArbitrumModel(_dstEid, _callDataSize, _gas);
    } else if (_dstEid == 111 || _dstEid == 10132 || _dstEid == 20132) {
        return _estimateFeeWithOptimismModel(_dstEid, _callDataSize, _gas);
    }
    // ...
}
```
- Hardcoded chain IDs
- No validation of model compatibility
- Potential for incorrect model selection

### Impact
- Price manipulation leading to incorrect fees
- Economic attacks through price updates
- Potential DoS through fee calculation exploits
- Cross-chain message failures due to incorrect fees
- Financial losses due to fee calculation errors

### Proof of Concept
```solidity
contract PriceFeedExploit {
    function demonstrateIssues(address priceFeed) external {
        PriceFeed p = PriceFeed(priceFeed);
        
        // 1. Price manipulation
        if (p.priceUpdater(address(this))) {
            // Set malicious prices
            UpdatePrice[] memory updates = new UpdatePrice[](1);
            updates[0] = UpdatePrice({
                eid: 1,
                price: Price({
                    priceRatio: type(uint128).max,
                    gasPriceInUnit: type(uint64).max,
                    gasPerByte: type(uint32).max
                })
            });
            p.setPrice(updates);
        }
        
        // 2. Fee calculation exploit
        // Cause overflow in fee calculation
        uint256 maxCallDataSize = type(uint256).max;
        uint256 maxGas = type(uint256).max;
        try p.estimateFeeByChain(110, maxCallDataSize, maxGas) {
            // Should overflow
        } catch {
            // Expected
        }
        
        // 3. Model selection exploit
        // Use incorrect model for chain
        uint16 invalidEid = 999;
        try p.estimateFeeByChain(invalidEid, 100, 100000) {
            // Should use default model
            // Could lead to incorrect fees
        } catch {
            // Expected
        }
    }
}
```

### Recommended Mitigation
1. Implement price update safety:
```solidity
contract PriceFeed {
    struct PriceUpdate {
        uint256 timestamp;
        uint256 value;
        bool pending;
    }
    
    uint256 public constant PRICE_UPDATE_DELAY = 1 hours;
    uint256 public constant MAX_PRICE_CHANGE = 50; // 50%
    
    mapping(uint32 => PriceUpdate) public pendingPriceUpdates;
    
    function proposePrice(UpdatePrice[] calldata _prices) external onlyPriceUpdater {
        for (uint256 i = 0; i < _prices.length; i++) {
            UpdatePrice calldata update = _prices[i];
            
            // Validate price change
            Price storage currentPrice = _defaultModelPrice[update.eid];
            uint256 priceChange = update.price.priceRatio > currentPrice.priceRatio
                ? update.price.priceRatio - currentPrice.priceRatio
                : currentPrice.priceRatio - update.price.priceRatio;
                
            require(
                priceChange <= (currentPrice.priceRatio * MAX_PRICE_CHANGE) / 100,
                "Price change too high"
            );
            
            // Create pending update
            pendingPriceUpdates[update.eid] = PriceUpdate({
                timestamp: block.timestamp,
                value: update.price.priceRatio,
                pending: true
            });
            
            emit PriceUpdateProposed(update.eid, update.price);
        }
    }
    
    function executePrice(uint32 _eid) external {
        PriceUpdate storage update = pendingPriceUpdates[_eid];
        require(update.pending, "No pending update");
        require(
            block.timestamp >= update.timestamp + PRICE_UPDATE_DELAY,
            "Too early"
        );
        
        // Apply update
        _defaultModelPrice[_eid].priceRatio = uint128(update.value);
        delete pendingPriceUpdates[_eid];
        
        emit PriceUpdateExecuted(_eid, update.value);
    }
}
```

2. Enhance fee calculations:
```solidity
contract PriceFeed {
    uint256 public constant MAX_CALLDATA_SIZE = 128 * 1024; // 128KB
    uint256 public constant MAX_GAS = 2000000;
    uint256 public constant MAX_FEE = 1000 ether;
    
    function _estimateFeeWithDefaultModel(
        uint32 _dstEid,
        uint256 _callDataSize,
        uint256 _gas
    ) internal view returns (uint256 fee, uint128 priceRatio) {
        require(_callDataSize <= MAX_CALLDATA_SIZE, "Calldata too large");
        require(_gas <= MAX_GAS, "Gas too high");
        
        Price storage remotePrice = _defaultModelPrice[_dstEid];
        require(remotePrice.priceRatio > 0, "Invalid price ratio");
        
        // Safe math operations
        uint256 gasForCallData = _callDataSize * remotePrice.gasPerByte;
        require(gasForCallData <= type(uint256).max - _gas, "Gas overflow");
        
        uint256 totalGas = gasForCallData + _gas;
        uint256 remoteFee = totalGas * remotePrice.gasPriceInUnit;
        require(remoteFee <= type(uint256).max / remotePrice.priceRatio, "Fee overflow");
        
        fee = (remoteFee * remotePrice.priceRatio) / PRICE_RATIO_DENOMINATOR;
        require(fee <= MAX_FEE, "Fee too high");
        
        return (fee, remotePrice.priceRatio);
    }
}
```

3. Improve model selection:
```solidity
contract PriceFeed {
    struct ChainConfig {
        ModelType modelType;
        bool active;
        uint256 lastUpdate;
    }
    
    mapping(uint32 => ChainConfig) public chainConfigs;
    
    function setChainConfig(
        uint32 _eid,
        ModelType _modelType,
        bool _active
    ) external onlyOwner {
        require(_modelType <= ModelType.OP_STACK, "Invalid model");
        
        chainConfigs[_eid] = ChainConfig({
            modelType: _modelType,
            active: _active,
            lastUpdate: block.timestamp
        });
        
        emit ChainConfigUpdated(_eid, _modelType, _active);
    }
    
    function estimateFeeByChain(
        uint32 _dstEid,
        uint256 _callDataSize,
        uint256 _gas
    ) external view returns (uint256 fee, uint128 priceRatio) {
        ChainConfig memory config = chainConfigs[_dstEid];
        require(config.active, "Chain not supported");
        
        if (config.modelType == ModelType.OP_STACK) {
            return _estimateFeeWithOptimismModel(_dstEid, _callDataSize, _gas);
        } else if (config.modelType == ModelType.ARB_STACK) {
            return _estimateFeeWithArbitrumModel(_dstEid, _callDataSize, _gas);
        } else {
            return _estimateFeeWithDefaultModel(_dstEid, _callDataSize, _gas);
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified