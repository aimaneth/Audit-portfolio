# Medium Severity Findings

## [M-01] Finding Title

### Description
[Detailed description of the finding]

### Impact
[Description of the potential impact]

### Proof of Concept
```solidity
// Code demonstrating the vulnerability
```

### Recommended Mitigation
[Detailed mitigation steps]

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-01] Insufficient Controls in Delegate Management System

### Description
The `EndpointV2.sol` contract implements a delegate system that allows OApps to authorize other addresses to configure their LayerZero settings. However, the current implementation lacks several critical security controls:

1. No validation on delegate addresses (could be set to zero address)
2. No mechanism to revoke delegation
3. No expiration mechanism for delegations
4. No events for delegation changes
5. No limit on number of times delegation can be changed

```solidity
function setDelegate(address _delegate) external {
    delegates[msg.sender] = _delegate;
    emit DelegateSet(msg.sender, _delegate);
}

function _assertAuthorized(address _oapp) internal view override {
    if (msg.sender != _oapp && msg.sender != delegates[_oapp]) 
        revert Errors.LZ_Unauthorized();
}
```

### Impact
- If a delegate address is compromised, there's no way to quickly revoke access
- Malicious delegate could manipulate OApp configurations indefinitely
- No way to implement proper access rotation policies
- Potential for privilege escalation if delegate is compromised

### Proof of Concept
```solidity
contract MaliciousDelegate {
    function attack(address endpoint, address[] calldata targets) external {
        // 1. OApp owner sets this contract as delegate
        // 2. Contract gets compromised
        // 3. Attacker can now:
        //    - Change message library configurations
        //    - Modify channel settings
        //    - Cannot be stopped without OApp owner intervention
        
        for(uint i = 0; i < targets.length; i++) {
            // Malicious configurations
            IEndpointV2(endpoint).setDefaultSendLibrary(targets[i]);
            // ... other malicious actions
        }
    }
}
```

### Recommended Mitigation
1. Add delegation revocation:
```solidity
mapping(address oapp => address delegate) public delegates;
mapping(address oapp => bool) public delegateRevoked;

function setDelegate(address _delegate) external {
    require(_delegate != address(0), "Invalid delegate");
    delegates[msg.sender] = _delegate;
    delegateRevoked[msg.sender] = false;
    emit DelegateSet(msg.sender, _delegate);
}

function revokeDelegate() external {
    delegateRevoked[msg.sender] = true;
    emit DelegateRevoked(msg.sender, delegates[msg.sender]);
}
```

2. Add delegation expiry:
```solidity
struct Delegation {
    address delegate;
    uint256 expiry;
}

mapping(address oapp => Delegation) public delegations;

function setDelegateWithExpiry(address _delegate, uint256 _duration) external {
    require(_delegate != address(0), "Invalid delegate");
    delegations[msg.sender] = Delegation({
        delegate: _delegate,
        expiry: block.timestamp + _duration
    });
    emit DelegateSet(msg.sender, _delegate, block.timestamp + _duration);
}
```

3. Add delegation limits:
```solidity
mapping(address oapp => uint256) public delegateChangeCount;
uint256 public constant MAX_DELEGATE_CHANGES = 3;

function setDelegate(address _delegate) external {
    require(_delegate != address(0), "Invalid delegate");
    require(delegateChangeCount[msg.sender] < MAX_DELEGATE_CHANGES, "Too many changes");
    delegates[msg.sender] = _delegate;
    delegateChangeCount[msg.sender]++;
    emit DelegateSet(msg.sender, _delegate);
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-02] Centralized Fee Control in SimpleMessageLib Lacks Safeguards

### Description
The `SimpleMessageLib.sol` contract implements a fee management system that is highly centralized and lacks important safety controls. The owner has unrestricted ability to modify fees without any bounds, delays, or notifications.

```solidity
function setMessagingFee(uint256 _nativeFee, uint256 _lzTokenFee) external onlyOwner {
    nativeFee = _nativeFee;
    lzTokenFee = _lzTokenFee;
}
```

Key issues:
1. No upper bounds on fee values
2. No timelock or delay mechanism
3. No gradual increase limits
4. No notification to users of fee changes
5. Single point of failure through owner

### Impact
- Owner could set arbitrarily high fees
- Users could be subject to unexpected fee changes
- No time for users to react to fee changes
- Potential for economic attacks through rapid fee manipulation

### Proof of Concept
```solidity
contract FeeManipulationExploit {
    function exploit(address messageLib) external {
        // Assuming attacker has gained owner access
        SimpleMessageLib lib = SimpleMessageLib(messageLib);
        
        // 1. Monitor for large pending transaction
        // 2. Front-run user tx with massive fee increase
        lib.setMessagingFee(
            type(uint256).max, // Set maximum possible fee
            type(uint256).max  // Set maximum possible LZ token fee
        );
        // 3. User transaction will revert due to insufficient fee
        // 4. Back-run to restore fees
        lib.setMessagingFee(100, 99);
    }
}

// Impact on users:
contract UserTransaction {
    function sendMessage(address messageLib, bytes memory message) external {
        // 1. User gets quote for fees
        (uint256 nativeFee, uint256 lzTokenFee) = messageLib.quote();
        
        // 2. User approves tokens and sends transaction
        // 3. Between quote and execution, fees could be changed arbitrarily
        // 4. Transaction fails or user pays extremely high fees
    }
}
```

### Recommended Mitigation
1. Implement fee change limits:
```solidity
contract SimpleMessageLib {
    uint256 public constant MAX_FEE = 1000;
    uint256 public constant MAX_FEE_INCREASE_PERCENT = 50;
    uint256 public constant FEE_CHANGE_DELAY = 1 days;
    
    struct PendingFee {
        uint256 nativeFee;
        uint256 lzTokenFee;
        uint256 effectiveTime;
    }
    
    PendingFee public pendingFee;
    
    function proposeNewFees(uint256 _nativeFee, uint256 _lzTokenFee) external onlyOwner {
        // Check maximum fee bounds
        require(_nativeFee <= MAX_FEE, "Native fee too high");
        require(_lzTokenFee <= MAX_FEE, "LZ token fee too high");
        
        // Check maximum increase
        require(_nativeFee <= nativeFee * (100 + MAX_FEE_INCREASE_PERCENT) / 100, "Increase too high");
        require(_lzTokenFee <= lzTokenFee * (100 + MAX_FEE_INCREASE_PERCENT) / 100, "Increase too high");
        
        // Set pending fee change
        pendingFee = PendingFee({
            nativeFee: _nativeFee,
            lzTokenFee: _lzTokenFee,
            effectiveTime: block.timestamp + FEE_CHANGE_DELAY
        });
        
        emit FeeChangeProposed(_nativeFee, _lzTokenFee, block.timestamp + FEE_CHANGE_DELAY);
    }
    
    function applyNewFees() external {
        require(block.timestamp >= pendingFee.effectiveTime, "Fee change not ready");
        require(pendingFee.effectiveTime != 0, "No pending fee change");
        
        nativeFee = pendingFee.nativeFee;
        lzTokenFee = pendingFee.lzTokenFee;
        
        delete pendingFee;
        
        emit FeeChangeApplied(nativeFee, lzTokenFee);
    }
}
```

2. Add emergency fee controls:
```solidity
contract SimpleMessageLib {
    bool public emergencyMode;
    uint256 public constant EMERGENCY_FEE_MULTIPLIER = 2;
    
    function enableEmergencyMode() external onlyOwner {
        emergencyMode = true;
        emit EmergencyModeEnabled();
    }
    
    function getEffectiveFees() public view returns (uint256 effectiveNativeFee, uint256 effectiveLzTokenFee) {
        effectiveNativeFee = emergencyMode ? nativeFee * EMERGENCY_FEE_MULTIPLIER : nativeFee;
        effectiveLzTokenFee = emergencyMode ? lzTokenFee * EMERGENCY_FEE_MULTIPLIER : lzTokenFee;
    }
}
```

3. Implement fee change notifications:
```solidity
contract SimpleMessageLib {
    mapping(address => bool) public feeNotifiers;
    
    function registerFeeNotifier(address notifier) external onlyOwner {
        feeNotifiers[notifier] = true;
    }
    
    function _notifyFeeChange(uint256 oldNativeFee, uint256 newNativeFee, uint256 oldLzTokenFee, uint256 newLzTokenFee) internal {
        // Notify all registered notifiers
        for (address notifier : feeNotifiers) {
            if (notifier != address(0)) {
                IFeeNotifier(notifier).onFeeChange(oldNativeFee, newNativeFee, oldLzTokenFee, newLzTokenFee);
            }
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-03] Unsafe Job Assignment in SendUlnBase Can Lead to Message Failures

### Description
The `SendUlnBase.sol` contract's job assignment mechanism lacks proper error handling and validation when interacting with DVN contracts. The current implementation makes unchecked external calls and doesn't properly handle DVN failures, which could lead to message delivery failures or stuck transactions.

```solidity
function _assignJobs(...) internal returns (uint256 totalFee, uint256[] memory dvnFees) {
    for (uint8 i = 0; i < dvnsLength; ++i) {
        address dvn = i < _ulnConfig.requiredDVNCount
            ? _ulnConfig.requiredDVNs[i]
            : _ulnConfig.optionalDVNs[i - _ulnConfig.requiredDVNCount];

        // Unchecked external call
        dvnFees[i] = ILayerZeroDVN(dvn).assignJob(_param, options);
    }
}
```

Key issues:
1. No validation of DVN contract existence
2. No try-catch around external calls
3. No distinction between required and optional DVN failures
4. No timeout mechanism for job assignments
5. No way to recover from failed assignments

### Impact
- Messages could fail if any required DVN fails
- No way to bypass failed DVNs
- Potential for permanently stuck messages
- Gas wasted on failed assignments
- No fallback mechanism for DVN failures

### Proof of Concept
```solidity
contract DVNExploit {
    function testDVNFailure(address sendUln, address maliciousDVN) external {
        // 1. Deploy malicious DVN that always reverts
        contract MaliciousDVN {
            function assignJob(AssignJobParam calldata _param, bytes calldata _options) external returns (uint256) {
                revert("DVN always fails");
            }
        }
        
        // 2. Configure it as a required DVN
        // (assuming attacker has gained configuration access)
        address[] memory requiredDVNs = new address[](1);
        requiredDVNs[0] = address(new MaliciousDVN());
        ISendUln(sendUln).setRequiredDVNs(requiredDVNs);
        
        // 3. All subsequent messages will fail
        // - No way to bypass the failing DVN
        // - No way to recover without admin intervention
        // - Messages could be permanently stuck
    }
}
```

### Recommended Mitigation
1. Implement proper error handling:
```solidity
contract SendUlnBase {
    error DVNAssignmentFailed(address dvn, string reason);
    
    function _assignJobs(...) internal returns (uint256 totalFee, uint256[] memory dvnFees) {
        for (uint8 i = 0; i < dvnsLength; ++i) {
            address dvn = _getDVNAddress(i, _ulnConfig);
            
            // Check DVN exists and has code
            require(dvn.code.length > 0, "DVN contract not deployed");
            
            try ILayerZeroDVN(dvn).assignJob(_param, options) returns (uint256 fee) {
                dvnFees[i] = fee;
            } catch Error(string memory reason) {
                if (i < _ulnConfig.requiredDVNCount) {
                    // Required DVN failed
                    revert DVNAssignmentFailed(dvn, reason);
                } else {
                    // Optional DVN failed - continue with others
                    emit DVNAssignmentSkipped(dvn, reason);
                }
            }
        }
    }
}
```

2. Add DVN health checks:
```solidity
contract SendUlnBase {
    mapping(address => uint256) public dvnFailureCount;
    uint256 public constant MAX_FAILURES = 3;
    
    function _assignJobs(...) internal {
        for (uint8 i = 0; i < dvnsLength; ++i) {
            address dvn = _getDVNAddress(i, _ulnConfig);
            
            // Check DVN health
            require(dvnFailureCount[dvn] < MAX_FAILURES, "DVN temporarily disabled");
            
            try ILayerZeroDVN(dvn).assignJob(_param, options) returns (uint256 fee) {
                // Success - reset failure count
                if (dvnFailureCount[dvn] > 0) {
                    dvnFailureCount[dvn] = 0;
                }
            } catch {
                // Increment failure count
                dvnFailureCount[dvn]++;
                emit DVNFailureCountIncremented(dvn, dvnFailureCount[dvn]);
                
                if (i < _ulnConfig.requiredDVNCount) {
                    revert("Required DVN failed");
                }
            }
        }
    }
}
```

3. Implement timeout mechanism:
```solidity
contract SendUlnBase {
    uint256 public constant JOB_TIMEOUT = 1 hours;
    
    struct JobAssignment {
        uint256 timestamp;
        bool completed;
    }
    
    mapping(bytes32 => JobAssignment) public jobAssignments;
    
    function _assignJobs(...) internal {
        bytes32 jobId = keccak256(abi.encode(_param));
        
        // Check for existing assignment
        if (jobAssignments[jobId].timestamp > 0) {
            require(
                block.timestamp > jobAssignments[jobId].timestamp + JOB_TIMEOUT,
                "Previous job not timed out"
            );
        }
        
        // Create new assignment
        jobAssignments[jobId] = JobAssignment({
            timestamp: block.timestamp,
            completed: false
        });
        
        // Rest of assignment logic
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-04] DVN Threshold Bypass Risk in ReceiveUlnBase

### Description
The `ReceiveUlnBase.sol` contract's verification threshold mechanism lacks proper validation and safety checks, which could allow messages to be verified with fewer DVN confirmations than intended. The issue lies in the threshold checking logic for optional DVNs.

```solidity
function _checkVerifiable(...) internal view returns (bool) {
    // ... required DVN checks ...

    // then it must require optional validations
    uint8 threshold = _config.optionalDVNThreshold;
    for (uint8 i = 0; i < _config.optionalDVNCount; ++i) {
        if (_verified(_config.optionalDVNs[i], _headerHash, _payloadHash, _config.confirmations)) {
            threshold--;
            if (threshold == 0) {
                return true;
            }
        }
    }
    return false;
}
```

Key issues:
1. No validation of threshold value
2. Threshold could be set to zero
3. No minimum threshold requirement
4. No relationship check between threshold and DVN count
5. No validation of DVN uniqueness

### Impact
- Messages could be verified with fewer confirmations than intended
- Security model could be compromised
- Potential for message verification bypass
- Reduced cross-chain security guarantees
- Possible centralization of verification power

### Proof of Concept
```solidity
contract ThresholdBypassExploit {
    function demonstrateBypasses(address receiveUln) external {
        // 1. Zero Threshold Attack
        UlnConfig memory config = UlnConfig({
            requiredDVNCount: 0,
            optionalDVNCount: 5,
            optionalDVNThreshold: 0,  // Set to zero
            confirmations: 1,
            requiredDVNs: new address[](0),
            optionalDVNs: new address[](5)
        });
        
        // Message will be verified without any DVN signatures
        bool verifiable = IReceiveUln(receiveUln).verifiable(
            config,
            bytes32(0),
            bytes32(0)
        );
        assert(verifiable == true);  // Will pass due to zero threshold
        
        // 2. Threshold > DVN Count Attack
        config.optionalDVNThreshold = 10;  // More than available DVNs
        config.optionalDVNCount = 5;
        
        // Message verification will be impossible
        verifiable = IReceiveUln(receiveUln).verifiable(
            config,
            bytes32(0),
            bytes32(0)
        );
        assert(verifiable == false);  // Will always fail
        
        // 3. Duplicate DVN Attack
        address[] memory dvns = new address[](5);
        dvns[0] = address(0x1);  // Same DVN repeated
        dvns[1] = address(0x1);
        dvns[2] = address(0x1);
        config.optionalDVNs = dvns;
        
        // Single DVN could satisfy multiple threshold requirements
    }
}
```

### Recommended Mitigation
1. Implement threshold validation:
```solidity
contract ReceiveUlnBase {
    uint8 public constant MIN_OPTIONAL_THRESHOLD = 1;
    
    function _validateConfig(UlnConfig memory _config) internal pure {
        // Validate threshold basics
        require(_config.optionalDVNThreshold >= MIN_OPTIONAL_THRESHOLD, "Threshold too low");
        require(_config.optionalDVNThreshold <= _config.optionalDVNCount, "Threshold too high");
        
        // Check DVN counts
        require(_config.optionalDVNCount <= type(uint8).max, "Too many DVNs");
        require(_config.requiredDVNCount + _config.optionalDVNCount > 0, "No DVNs configured");
        
        // Validate DVN arrays
        require(_config.requiredDVNs.length == _config.requiredDVNCount, "Invalid required DVN count");
        require(_config.optionalDVNs.length == _config.optionalDVNCount, "Invalid optional DVN count");
        
        // Check for duplicates
        address[] memory allDvns = new address[](_config.requiredDVNCount + _config.optionalDVNCount);
        uint256 idx = 0;
        
        for (uint8 i = 0; i < _config.requiredDVNCount; i++) {
            require(_config.requiredDVNs[i] != address(0), "Invalid DVN address");
            allDvns[idx++] = _config.requiredDVNs[i];
        }
        
        for (uint8 i = 0; i < _config.optionalDVNCount; i++) {
            require(_config.optionalDVNs[i] != address(0), "Invalid DVN address");
            allDvns[idx++] = _config.optionalDVNs[i];
        }
        
        // Check for duplicates
        for (uint256 i = 0; i < allDvns.length; i++) {
            for (uint256 j = i + 1; j < allDvns.length; j++) {
                require(allDvns[i] != allDvns[j], "Duplicate DVN");
            }
        }
    }
}
```

2. Add dynamic threshold adjustment:
```solidity
contract ReceiveUlnBase {
    struct ThresholdConfig {
        uint8 baseThreshold;
        uint8 dynamicMultiplier;
        uint256 lastUpdateTime;
    }
    
    mapping(uint32 => ThresholdConfig) public chainThresholds;
    
    function _getDynamicThreshold(uint32 _chainId, uint8 _dvnCount) internal view returns (uint8) {
        ThresholdConfig storage config = chainThresholds[_chainId];
        
        // Increase threshold based on chain risk
        uint8 threshold = config.baseThreshold;
        
        // Add dynamic component
        threshold += (_dvnCount * config.dynamicMultiplier) / 100;
        
        // Ensure within bounds
        if (threshold > _dvnCount) {
            threshold = _dvnCount;
        }
        if (threshold < MIN_OPTIONAL_THRESHOLD) {
            threshold = MIN_OPTIONAL_THRESHOLD;
        }
        
        return threshold;
    }
}
```

3. Implement threshold verification tracking:
```solidity
contract ReceiveUlnBase {
    struct VerificationProgress {
        uint8 requiredCount;
        uint8 optionalCount;
        uint256 startTime;
        mapping(address => bool) hasVerified;
    }
    
    mapping(bytes32 => VerificationProgress) public verificationProgress;
    
    function _checkVerifiable(...) internal returns (bool) {
        bytes32 verificationId = keccak256(abi.encodePacked(_headerHash, _payloadHash));
        VerificationProgress storage progress = verificationProgress[verificationId];
        
        // Initialize if new
        if (progress.startTime == 0) {
            progress.startTime = block.timestamp;
        }
        
        // Track unique verifications
        for (uint8 i = 0; i < _config.optionalDVNCount; i++) {
            address dvn = _config.optionalDVNs[i];
            if (!progress.hasVerified[dvn] && _verified(dvn, _headerHash, _payloadHash, _config.confirmations)) {
                progress.hasVerified[dvn] = true;
                progress.optionalCount++;
            }
        }
        
        return progress.optionalCount >= _config.optionalDVNThreshold;
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-05] ULN302 Configuration Race Condition

### Description
The `SendUln302.sol` and `ReceiveUln302.sol` contracts' configuration management system lacks proper synchronization and version control mechanisms. The current implementation allows configurations to be updated without any delay or validation, which could lead to inconsistencies in cross-chain message processing.

```solidity
// SendUln302.sol
function setConfig(address _oapp, SetConfigParam[] calldata _params) external override onlyEndpoint {
    for (uint256 i = 0; i < _params.length; i++) {
        SetConfigParam calldata param = _params[i];
        _assertSupportedEid(param.eid);
        if (param.configType == CONFIG_TYPE_EXECUTOR) {
            _setExecutorConfig(param.eid, _oapp, abi.decode(param.config, (ExecutorConfig)));
        } else if (param.configType == CONFIG_TYPE_ULN) {
            _setUlnConfig(param.eid, _oapp, abi.decode(param.config, (UlnConfig)));
        }
    }
}
```

Key issues:
1. No version tracking for configurations
2. No delay between config changes
3. No validation of config compatibility
4. No synchronization between send/receive sides
5. No event emission for config changes

### Impact
- Messages could be processed with inconsistent configurations
- Cross-chain communication could fail due to config mismatches
- No way to track configuration changes
- Potential for message delivery failures
- Difficult to debug configuration issues

### Proof of Concept
```solidity
contract ConfigRaceExploit {
    function demonstrateRace(address sendUln, address receiveUln) external {
        // 1. Initial state
        // Chain A: Config A1
        // Chain B: Config B1
        
        // 2. Message sent from Chain A to B
        // - Uses Config A1 for sending
        // - Message in transit
        
        // 3. Config updated on Chain B
        SetConfigParam[] memory params = new SetConfigParam[](1);
        params[0] = SetConfigParam({
            eid: CHAIN_A_EID,
            configType: CONFIG_TYPE_ULN,
            config: abi.encode(NEW_CONFIG)  // B2
        });
        
        IReceiveUln302(receiveUln).setConfig(oapp, params);
        
        // 4. Message arrives on Chain B
        // - Sent with Config A1
        // - Received with Config B2
        // - Verification fails due to mismatch
        
        // Result:
        // - Message stuck or failed
        // - No way to recover
        // - Config mismatch between chains
    }
}
```

### Recommended Mitigation
1. Implement configuration versioning:
```solidity
contract SendUln302 {
    struct ConfigVersion {
        uint256 version;
        uint256 effectiveTime;
        bytes config;
    }
    
    mapping(address => mapping(uint32 => ConfigVersion)) public configs;
    uint256 public constant CONFIG_DELAY = 1 days;
    
    function setConfig(address _oapp, SetConfigParam[] calldata _params) external {
        for (uint256 i = 0; i < _params.length; i++) {
            ConfigVersion storage cv = configs[_oapp][_params[i].eid];
            
            // Enforce delay
            require(
                block.timestamp >= cv.effectiveTime + CONFIG_DELAY,
                "Config change too soon"
            );
            
            // Update version
            cv.version++;
            cv.effectiveTime = block.timestamp;
            cv.config = _params[i].config;
            
            emit ConfigUpdated(_oapp, _params[i].eid, cv.version);
        }
    }
}
```

2. Add configuration validation:
```solidity
contract UlnBase {
    function _validateConfig(UlnConfig memory _config) internal pure {
        // Validate DVN settings
        require(_config.requiredDVNCount > 0, "No required DVNs");
        require(_config.optionalDVNCount <= MAX_OPTIONAL_DVNS, "Too many optional DVNs");
        
        // Validate threshold
        require(
            _config.optionalDVNThreshold <= _config.optionalDVNCount,
            "Invalid threshold"
        );
        
        // Validate confirmations
        require(
            _config.confirmations >= MIN_CONFIRMATIONS,
            "Confirmations too low"
        );
        
        // Validate DVN addresses
        for (uint i = 0; i < _config.requiredDVNCount; i++) {
            require(_config.requiredDVNs[i] != address(0), "Invalid DVN address");
        }
    }
}
```

3. Implement configuration synchronization:
```solidity
contract Uln302Base {
    struct ConfigSync {
        uint256 sendVersion;
        uint256 receiveVersion;
        bool synchronized;
    }
    
    mapping(address => mapping(uint32 => ConfigSync)) public configSync;
    
    function _syncConfig(
        address _oapp,
        uint32 _eid,
        uint256 _sendVersion,
        uint256 _receiveVersion
    ) internal {
        ConfigSync storage sync = configSync[_oapp][_eid];
        
        // Update versions
        sync.sendVersion = _sendVersion;
        sync.receiveVersion = _receiveVersion;
        
        // Check sync status
        sync.synchronized = (
            _sendVersion == _receiveVersion &&
            configs[_oapp][_eid].version == _sendVersion
        );
        
        emit ConfigSyncStatus(_oapp, _eid, sync.synchronized);
    }
    
    function _requireConfigSync(address _oapp, uint32 _eid) internal view {
        require(
            configSync[_oapp][_eid].synchronized,
            "Config not synchronized"
        );
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-06] DVN Adapter Library Configuration Issues

### Description
The `DVNAdapterBase.sol` contract's library configuration mechanism lacks proper validation and version control. The current implementation allows setting receive libraries without validation of addresses or version compatibility, which could lead to misconfiguration and potential message failures.

```solidity
contract DVNAdapterBase is Worker, ILayerZeroDVN {
    mapping(address sendLib => mapping(uint32 dstEid => bytes32 receiveLib)) public receiveLibs;
    
    function setReceiveLibs(ReceiveLibParam[] calldata _params) external onlyRole(DEFAULT_ADMIN_ROLE) {
        for (uint256 i = 0; i < _params.length; i++) {
            ReceiveLibParam calldata param = _params[i];
            receiveLibs[param.sendLib][param.dstEid] = param.receiveLib;
        }
        emit ReceiveLibsSet(_params);
    }
}
```

Key issues:
1. No validation of library addresses
2. No version control for libraries
3. No compatibility checks between send/receive libraries
4. No delay in library updates
5. No events for individual library changes

### Impact
- Libraries could be misconfigured
- Incompatible versions could be set
- Messages could fail due to library mismatches
- No way to track library changes
- Difficult to debug configuration issues

### Proof of Concept
```solidity
contract AdapterConfigExploit {
    function demonstrateIssues(address adapter) external {
        // 1. Set invalid library
        ReceiveLibParam[] memory params = new ReceiveLibParam[](1);
        params[0] = ReceiveLibParam({
            sendLib: address(0),  // Invalid address
            dstEid: 1,
            receiveLib: bytes32(0)  // Invalid library
        });
        
        IDVNAdapter(adapter).setReceiveLibs(params);
        // No validation, sets invalid config
        
        // 2. Version mismatch
        params[0] = ReceiveLibParam({
            sendLib: address(0x123),  // SendLib v1
            dstEid: 1,
            receiveLib: bytes32(keccak256("ReceiveLib v2"))  // Incompatible version
        });
        
        IDVNAdapter(adapter).setReceiveLibs(params);
        // No version check, sets incompatible versions
        
        // 3. Race condition
        // Thread 1: Sets library A
        params[0].receiveLib = bytes32(keccak256("LibraryA"));
        IDVNAdapter(adapter).setReceiveLibs(params);
        
        // Thread 2: Sets library B
        params[0].receiveLib = bytes32(keccak256("LibraryB"));
        IDVNAdapter(adapter).setReceiveLibs(params);
        
        // Messages in transit could use either library
        // No way to track which library was used
    }
}
```

### Recommended Mitigation
1. Implement library validation:
```solidity
contract DVNAdapterBase {
    struct LibraryConfig {
        bytes32 receiveLib;
        uint256 version;
        bool active;
    }
    
    mapping(address => mapping(uint32 => LibraryConfig)) public libraryConfigs;
    
    function setReceiveLib(
        address _sendLib,
        uint32 _dstEid,
        bytes32 _receiveLib,
        uint256 _version
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Validate addresses
        require(_sendLib != address(0), "Invalid send lib");
        require(_receiveLib != bytes32(0), "Invalid receive lib");
        
        // Check version compatibility
        require(_version >= MIN_VERSION, "Version too low");
        require(_version <= MAX_VERSION, "Version too high");
        
        // Update config
        libraryConfigs[_sendLib][_dstEid] = LibraryConfig({
            receiveLib: _receiveLib,
            version: _version,
            active: true
        });
        
        emit ReceiveLibSet(_sendLib, _dstEid, _receiveLib, _version);
    }
}
```

2. Add configuration timelock:
```solidity
contract DVNAdapterBase {
    struct PendingLibrary {
        bytes32 receiveLib;
        uint256 version;
        uint256 effectiveTime;
    }
    
    mapping(address => mapping(uint32 => PendingLibrary)) public pendingLibraries;
    uint256 public constant LIBRARY_UPDATE_DELAY = 1 days;
    
    function proposeReceiveLib(
        address _sendLib,
        uint32 _dstEid,
        bytes32 _receiveLib,
        uint256 _version
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        // Validate inputs
        require(_sendLib != address(0), "Invalid send lib");
        require(_receiveLib != bytes32(0), "Invalid receive lib");
        
        // Set pending update
        pendingLibraries[_sendLib][_dstEid] = PendingLibrary({
            receiveLib: _receiveLib,
            version: _version,
            effectiveTime: block.timestamp + LIBRARY_UPDATE_DELAY
        });
        
        emit ReceiveLibProposed(_sendLib, _dstEid, _receiveLib, _version);
    }
    
    function applyReceiveLib(
        address _sendLib,
        uint32 _dstEid
    ) external {
        PendingLibrary storage pending = pendingLibraries[_sendLib][_dstEid];
        require(pending.effectiveTime > 0, "No pending update");
        require(block.timestamp >= pending.effectiveTime, "Too early");
        
        // Update config
        libraryConfigs[_sendLib][_dstEid] = LibraryConfig({
            receiveLib: pending.receiveLib,
            version: pending.version,
            active: true
        });
        
        delete pendingLibraries[_sendLib][_dstEid];
        emit ReceiveLibApplied(_sendLib, _dstEid, pending.receiveLib, pending.version);
    }
}
```

3. Implement version compatibility:
```solidity
contract DVNAdapterBase {
    struct VersionRange {
        uint256 minVersion;
        uint256 maxVersion;
    }
    
    mapping(address => VersionRange) public sendLibVersions;
    mapping(bytes32 => VersionRange) public receiveLibVersions;
    
    function setSendLibVersion(
        address _sendLib,
        uint256 _minVersion,
        uint256 _maxVersion
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_minVersion <= _maxVersion, "Invalid version range");
        sendLibVersions[_sendLib] = VersionRange(_minVersion, _maxVersion);
    }
    
    function setReceiveLibVersion(
        bytes32 _receiveLib,
        uint256 _minVersion,
        uint256 _maxVersion
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(_minVersion <= _maxVersion, "Invalid version range");
        receiveLibVersions[_receiveLib] = VersionRange(_minVersion, _maxVersion);
    }
    
    function _validateVersionCompatibility(
        address _sendLib,
        bytes32 _receiveLib,
        uint256 _version
    ) internal view {
        VersionRange storage sendRange = sendLibVersions[_sendLib];
        VersionRange storage receiveRange = receiveLibVersions[_receiveLib];
        
        require(_version >= sendRange.minVersion, "Send version too low");
        require(_version <= sendRange.maxVersion, "Send version too high");
        require(_version >= receiveRange.minVersion, "Receive version too low");
        require(_version <= receiveRange.maxVersion, "Receive version too high");
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-03] Decimal Conversion Precision Loss and Dust Accumulation in OFT

### Description
The `OFTCore.sol` contract implements a decimal conversion system for handling tokens with different decimal places across chains. The current implementation in `_removeDust` and decimal conversion functions can lead to precision loss and dust accumulation over multiple transfers.

```solidity
function _removeDust(uint256 _amountLD) internal view virtual returns (uint256 amountLD) {
    return (_amountLD / decimalConversionRate) * decimalConversionRate;
}

function _toLD(uint64 _amountSD) internal view virtual returns (uint256 amountLD) {
    return _amountSD * decimalConversionRate;
}

function _toSD(uint256 _amountLD) internal view virtual returns (uint64 amountSD) {
    return uint64(_amountLD / decimalConversionRate);
}
```

Key issues:
1. Dust removal truncates amounts without tracking lost precision
2. No mechanism to recover or account for accumulated dust
3. Potential for significant value loss over multiple transfers
4. Rounding always down can lead to systematic value loss
5. No minimum transfer amount to prevent dust creation

### Impact
- Gradual loss of token value through dust accumulation
- Precision loss in cross-chain transfers
- Systematic undervaluation of token amounts
- Potential for economic attacks exploiting rounding
- User confusion due to unexpected amount changes

### Proof of Concept
```solidity
contract OFTDecimalExploit {
    function demonstrateDustLoss(address oft, uint32 dstEid) external {
        IOFT token = IOFT(oft);
        
        // 1. Initial balance: 1000 tokens with 18 decimals
        // Assuming shared decimals is 6
        uint256 initialBalance = 1000 * 10**18;
        
        // 2. Perform multiple small transfers
        for(uint i = 0; i < 10; i++) {
            // Transfer amount that will create dust
            uint256 amount = 1 * 10**18 + 123456789;
            
            SendParam memory param = SendParam({
                dstEid: dstEid,
                to: bytes32(uint256(uint160(address(this)))),
                amountLD: amount,
                minAmountLD: 0,
                extraOptions: "",
                composeMsg: "",
                oftCmd: ""
            });
            
            // Each transfer loses dust due to decimal conversion
            token.send(param, MessagingFee(0, 0), address(this));
        }
        
        // 3. Final balance will be less than expected due to accumulated dust loss
        // Lost precision = (123456789 * 10) = 1.23456789 tokens
    }
}
```

### Recommended Mitigation
1. Implement dust tracking and recovery:
```solidity
contract OFTCore {
    // Track dust per user
    mapping(address => uint256) public accumulatedDust;
    
    function _removeDust(uint256 _amountLD, address _user) internal returns (uint256 amountLD) {
        uint256 newAmount = (_amountLD / decimalConversionRate) * decimalConversionRate;
        uint256 dust = _amountLD - newAmount;
        
        if (dust > 0) {
            accumulatedDust[_user] += dust;
        }
        
        return newAmount;
    }
    
    // Allow users to claim accumulated dust when it reaches a significant amount
    function claimDust() external {
        uint256 dust = accumulatedDust[msg.sender];
        require(dust >= decimalConversionRate, "Insufficient dust");
        
        uint256 claimableAmount = (dust / decimalConversionRate) * decimalConversionRate;
        accumulatedDust[msg.sender] = dust - claimableAmount;
        
        _transfer(address(this), msg.sender, claimableAmount);
    }
}
```

2. Add minimum transfer amount:
```solidity
contract OFTCore {
    uint256 public constant MIN_TRANSFER_AMOUNT = 1000; // Adjust based on decimals
    
    function _debit(
        address _from,
        uint256 _amountLD,
        uint256 _minAmountLD,
        uint32 _dstEid
    ) internal virtual returns (uint256 amountSentLD, uint256 amountReceivedLD) {
        require(_amountLD >= MIN_TRANSFER_AMOUNT, "Amount too small");
        // ... rest of the function
    }
}
```

3. Implement rounding options:
```solidity
contract OFTCore {
    enum RoundingMode { DOWN, UP, NEAREST }
    
    function _removeDust(
        uint256 _amountLD,
        RoundingMode _mode
    ) internal view returns (uint256) {
        uint256 quotient = _amountLD / decimalConversionRate;
        uint256 remainder = _amountLD % decimalConversionRate;
        
        if (_mode == RoundingMode.DOWN) {
            return quotient * decimalConversionRate;
        } else if (_mode == RoundingMode.UP && remainder > 0) {
            return (quotient + 1) * decimalConversionRate;
        } else if (_mode == RoundingMode.NEAREST) {
            return remainder >= decimalConversionRate / 2
                ? (quotient + 1) * decimalConversionRate
                : quotient * decimalConversionRate;
        }
        
        return quotient * decimalConversionRate;
    }
}
```

4. Add precision loss warnings:
```solidity
contract OFTCore {
    event PrecisionLoss(
        address indexed user,
        uint256 originalAmount,
        uint256 convertedAmount,
        uint256 dust
    );
    
    function _removeDust(uint256 _amountLD) internal returns (uint256) {
        uint256 newAmount = (_amountLD / decimalConversionRate) * decimalConversionRate;
        uint256 dust = _amountLD - newAmount;
        
        if (dust > 0) {
            emit PrecisionLoss(msg.sender, _amountLD, newAmount, dust);
        }
        
        return newAmount;
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-07] OFTAdapter Approval Management Vulnerabilities

### Description
The `OFTAdapter.sol` contract's approval management system has several security issues related to token approvals and permissions. The current implementation requires users to approve potentially unlimited amounts and lacks proper approval validation and revocation mechanisms.

```solidity
contract OFTAdapter is OFTCore {
    using SafeERC20 for IERC20;
    
    function approvalRequired() external pure virtual returns (bool) {
        return true;  // Always requires approval
    }
    
    function _debit(address _from, uint256 _amountLD, ...) internal virtual override {
        // No approval amount validation
        // No approval expiry check
        innerToken.safeTransferFrom(_from, address(this), amountSentLD);
    }
}
```

Key issues:
1. No maximum approval limits
2. Missing approval expiration mechanism
3. No approval revocation functionality
4. Potential for approval front-running
5. Complex cross-chain approval inheritance

### Impact
- Users must approve large or unlimited amounts
- Approvals cannot be easily revoked
- Potential for approval misuse
- Front-running risks on approvals
- Complex approval management across chains

### Proof of Concept
```solidity
contract ApprovalExploit {
    function demonstrateIssues(address adapter, address token) external {
        IERC20 innerToken = IERC20(token);
        
        // 1. User must approve large amount for cross-chain transfers
        uint256 amount = type(uint256).max;  // Unlimited approval
        innerToken.approve(adapter, amount);
        
        // 2. Front-running attack
        // User: approve(adapter, 1000)
        // Attacker: transfer 1000 tokens [front-run]
        // User's tx: fails
        // User: approve(adapter, 1000) [retry]
        // Attacker: transfer another 1000 tokens
        // Result: User loses 2000 tokens
        
        // 3. No way to partially revoke
        // User wants to reduce approval to 500
        // But must first set to 0, then to 500
        // This creates a front-running opportunity
        innerToken.approve(adapter, 0);
        innerToken.approve(adapter, 500);
    }
}
```

### Recommended Mitigation
1. Implement approval limits and tracking:
```solidity
contract OFTAdapter {
    struct ApprovalInfo {
        uint256 amount;
        uint256 expiry;
        bool used;
    }
    
    // Track approvals per user
    mapping(address => ApprovalInfo) public approvals;
    uint256 public constant MAX_APPROVAL = 1000000e18;
    
    function setApproval(uint256 _amount, uint256 _duration) external {
        require(_amount <= MAX_APPROVAL, "Approval too high");
        
        approvals[msg.sender] = ApprovalInfo({
            amount: _amount,
            expiry: block.timestamp + _duration,
            used: false
        });
        
        // Get approval from user
        innerToken.safeTransferFrom(msg.sender, address(this), _amount);
        
        emit ApprovalSet(msg.sender, _amount, block.timestamp + _duration);
    }
    
    function revokeApproval() external {
        ApprovalInfo storage info = approvals[msg.sender];
        require(info.amount > 0, "No approval");
        
        // Return unused tokens
        uint256 unused = info.amount;
        delete approvals[msg.sender];
        
        innerToken.safeTransfer(msg.sender, unused);
        emit ApprovalRevoked(msg.sender, unused);
    }
}
```

2. Add approval safety checks:
```solidity
contract OFTAdapter {
    function _validateApproval(
        address _user,
        uint256 _amount
    ) internal view returns (bool) {
        ApprovalInfo storage info = approvals[_user];
        
        require(info.amount >= _amount, "Insufficient approval");
        require(block.timestamp <= info.expiry, "Approval expired");
        require(!info.used, "Approval already used");
        
        return true;
    }
    
    function _debit(
        address _from,
        uint256 _amountLD,
        uint256 _minAmountLD,
        uint32 _dstEid
    ) internal virtual override returns (uint256, uint256) {
        // Validate approval
        require(_validateApproval(_from, _amountLD), "Invalid approval");
        
        // Mark approval as used
        approvals[_from].used = true;
        
        // Execute transfer
        innerToken.safeTransferFrom(_from, address(this), _amountLD);
        
        return (_amountLD, _amountLD);
    }
}
```

3. Implement approval inheritance:
```solidity
contract OFTAdapter {
    struct CrossChainApproval {
        uint32 srcChain;
        uint256 amount;
        uint256 nonce;
        bytes signature;
    }
    
    mapping(bytes32 => bool) public usedApprovals;
    
    function verifyCrossChainApproval(
        address _user,
        CrossChainApproval memory _approval
    ) internal returns (bool) {
        // Generate approval hash
        bytes32 approvalHash = keccak256(abi.encode(
            _user,
            _approval.srcChain,
            _approval.amount,
            _approval.nonce
        ));
        
        // Check if already used
        require(!usedApprovals[approvalHash], "Approval used");
        
        // Verify signature
        require(
            _verifySignature(_user, approvalHash, _approval.signature),
            "Invalid signature"
        );
        
        // Mark as used
        usedApprovals[approvalHash] = true;
        
        return true;
    }
}
```

4. Add approval events and monitoring:
```solidity
contract OFTAdapter {
    event ApprovalSet(address indexed user, uint256 amount, uint256 expiry);
    event ApprovalUsed(address indexed user, uint256 amount, uint32 dstChain);
    event ApprovalRevoked(address indexed user, uint256 amount);
    event CrossChainApprovalVerified(
        address indexed user,
        uint32 srcChain,
        uint256 amount,
        uint256 nonce
    );
    
    function _trackApprovalUsage(
        address _user,
        uint256 _amount,
        uint32 _dstChain
    ) internal {
        emit ApprovalUsed(_user, _amount, _dstChain);
    }
    
    function getApprovalStatus(
        address _user
    ) external view returns (
        uint256 amount,
        uint256 expiry,
        bool used
    ) {
        ApprovalInfo storage info = approvals[_user];
        return (info.amount, info.expiry, info.used);
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-08] Endpoint Message Verification Race Conditions and Execution Vulnerabilities

### Description
The `EndpointV2.sol` contract's message verification and execution flow has several potential vulnerabilities related to race conditions and execution ordering. The current implementation separates message verification and execution into two steps, which could lead to potential issues.

```solidity
contract EndpointV2 {
    function verify(Origin calldata _origin, address _receiver, bytes32 _payloadHash) external {
        // Verification step
        if (!isValidReceiveLibrary(_receiver, _origin.srcEid, msg.sender)) revert Errors.LZ_InvalidReceiveLibrary();
        
        uint64 lazyNonce = lazyInboundNonce[_receiver][_origin.srcEid][_origin.sender];
        if (!_initializable(_origin, _receiver, lazyNonce)) revert Errors.LZ_PathNotInitializable();
        if (!_verifiable(_origin, _receiver, lazyNonce)) revert Errors.LZ_PathNotVerifiable();
        
        _inbound(_receiver, _origin.srcEid, _origin.sender, _origin.nonce, _payloadHash);
    }
    
    function lzReceive(
        Origin calldata _origin,
        address _receiver,
        bytes32 _guid,
        bytes calldata _message,
        bytes calldata _extraData
    ) external payable {
        // Execution step
        _clearPayload(_receiver, _origin.srcEid, _origin.sender, _origin.nonce, abi.encodePacked(_guid, _message));
        ILayerZeroReceiver(_receiver).lzReceive{ value: msg.value }(
            _origin,
            _guid,
            _message,
            msg.sender,
            _extraData
        );
    }
}
```

Key issues:
1. Race conditions between verification and execution
2. No timeout mechanism for verified but unexecuted messages
3. Potential for message reordering
4. Missing validation of `_extraData` length and content
5. Insufficient checks for message value transfers

### Impact
- Messages could be executed out of order
- Verified messages might never be executed
- Potential for message execution front-running
- Possible DoS through message value manipulation
- Memory exhaustion through large `_extraData`

### Proof of Concept
```solidity
contract EndpointExploit {
    function demonstrateIssues(
        address endpoint,
        Origin memory origin,
        address receiver,
        bytes32 guid,
        bytes memory message
    ) external {
        // 1. Message ordering attack
        // Attacker front-runs with a different message
        ILayerZeroEndpointV2(endpoint).lzReceive(
            origin,
            receiver,
            guid,
            message,
            new bytes(0)
        );
        
        // 2. Value manipulation attack
        // Send with excessive value to cause reverts
        ILayerZeroEndpointV2(endpoint).lzReceive{value: type(uint256).max}(
            origin,
            receiver,
            guid,
            message,
            new bytes(0)
        );
        
        // 3. Memory exhaustion attack
        // Send with huge extraData
        bytes memory largeExtraData = new bytes(2**30);  // 1GB
        ILayerZeroEndpointV2(endpoint).lzReceive(
            origin,
            receiver,
            guid,
            message,
            largeExtraData
        );
    }
}
```

### Recommended Mitigation
1. Implement message execution ordering:
```solidity
contract EndpointV2 {
    struct MessageQueue {
        uint64 nextNonce;
        mapping(uint64 => bytes32) messages;
    }
    
    mapping(address => mapping(uint32 => mapping(bytes32 => MessageQueue))) private messageQueues;
    
    function lzReceive(
        Origin calldata _origin,
        address _receiver,
        bytes32 _guid,
        bytes calldata _message,
        bytes calldata _extraData
    ) external payable {
        MessageQueue storage queue = messageQueues[_receiver][_origin.srcEid][_origin.sender];
        
        // Ensure messages are executed in order
        require(_origin.nonce == queue.nextNonce, "Wrong nonce");
        
        // Validate extraData size
        require(_extraData.length <= MAX_EXTRA_DATA_SIZE, "ExtraData too large");
        
        // Clear payload before execution
        _clearPayload(_receiver, _origin.srcEid, _origin.sender, _origin.nonce, abi.encodePacked(_guid, _message));
        
        // Update queue
        queue.nextNonce++;
        
        // Execute with value validation
        require(msg.value <= MAX_MESSAGE_VALUE, "Value too large");
        ILayerZeroReceiver(_receiver).lzReceive{ value: msg.value }(
            _origin,
            _guid,
            _message,
            msg.sender,
            _extraData
        );
    }
}
```

2. Add message timeout mechanism:
```solidity
contract EndpointV2 {
    uint256 public constant MESSAGE_TIMEOUT = 7 days;
    mapping(bytes32 => uint256) public messageTimestamps;
    
    function verify(Origin calldata _origin, address _receiver, bytes32 _payloadHash) external {
        // ... existing verification ...
        
        // Record verification timestamp
        bytes32 messageId = keccak256(abi.encode(_origin, _receiver));
        messageTimestamps[messageId] = block.timestamp;
    }
    
    function lzReceive(
        Origin calldata _origin,
        address _receiver,
        bytes32 _guid,
        bytes calldata _message,
        bytes calldata _extraData
    ) external payable {
        bytes32 messageId = keccak256(abi.encode(_origin, _receiver));
        require(
            block.timestamp - messageTimestamps[messageId] <= MESSAGE_TIMEOUT,
            "Message expired"
        );
        
        // ... rest of execution ...
    }
}
```

3. Implement value and data validation:
```solidity
contract EndpointV2 {
    uint256 public constant MAX_MESSAGE_VALUE = 100 ether;
    uint256 public constant MAX_EXTRA_DATA_SIZE = 10_000;  // 10KB
    
    function lzReceive(
        Origin calldata _origin,
        address _receiver,
        bytes32 _guid,
        bytes calldata _message,
        bytes calldata _extraData
    ) external payable {
        // Validate message size
        require(_message.length <= MAX_MESSAGE_SIZE, "Message too large");
        require(_extraData.length <= MAX_EXTRA_DATA_SIZE, "ExtraData too large");
        
        // Get message info
        MessageQueue storage msg = messageQueues[_from][_to][_guid][_index];
        require(!msg.isDelivered, "Already delivered");
        require(
            block.timestamp <= msg.timestamp + MESSAGE_EXPIRY,
            "Message expired"
        );
        
        // Verify message hash
        bytes32 actualHash = keccak256(_message);
        require(msg.messageHash == actualHash, "Invalid message");
        
        // Mark as delivered before external call
        msg.isDelivered = true;
        
        // Make external call
        try ILayerZeroComposer(_to).lzCompose{ value: msg.value }(
            _from,
            _guid,
            _message,
            msg.sender,
            _extraData
        ) {
            emit ComposeDelivered(_from, _to, _guid, _index);
        } catch (bytes memory reason) {
            // Revert delivery status on failure
            msg.isDelivered = false;
            emit LzComposeAlert(
                _from,
                _to,
                msg.sender,
                _guid,
                _index,
                gasleft(),
                msg.value,
                _message,
                _extraData,
                reason
            );
            revert(string(reason));
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-09] Message Library Management Vulnerabilities in Timeout and Version Control

### Description
The `MessageLibManager.sol` contract's library management system has several potential vulnerabilities related to timeout mechanisms and version control. The current implementation allows for complex library transitions and timeout configurations that could lead to security issues.

```solidity
contract MessageLibManager {
    mapping(address receiver => mapping(uint32 srcEid => mapping(bytes32 sender => uint64 nonce)))
        public lazyInboundNonce;
    mapping(address receiver => mapping(uint32 srcEid => mapping(bytes32 sender => mapping(uint64 inboundNonce => bytes32 payloadHash))))
        public inboundPayloadHash;
    
    function _inbound(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce,
        bytes32 _payloadHash
    ) internal {
        // No strict ordering enforcement
        if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();
        inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
    }
    
    function skip(address _oapp, uint32 _srcEid, bytes32 _sender, uint64 _nonce) external {
        // Potential for nonce manipulation
        if (_nonce != inboundNonce(_oapp, _srcEid, _sender) + 1) revert Errors.LZ_InvalidNonce(_nonce);
        lazyInboundNonce[_oapp][_srcEid][_sender] = _nonce;
    }
}
```

Key issues:
1. Unordered message verification
2. Nonce skipping vulnerabilities
3. Lazy nonce updates
4. Message reordering possibilities
5. Insufficient payload verification

### Impact
- Messages can be verified out of order
- Potential for nonce manipulation
- Race conditions in message processing
- Possible message reordering attacks
- Inconsistent message states

### Proof of Concept
```solidity
contract MessagingChannelExploit {
    function demonstrateIssues(
        address channel,
        address oapp,
        uint32 srcEid,
        bytes32 sender
    ) external {
        // 1. Message ordering attack
        // Verify messages out of order
        bytes32 payload1 = keccak256("message1");
        bytes32 payload2 = keccak256("message2");
        
        // Verify nonce 2 before nonce 1
        IMessagingChannel(channel).verify(
            Origin(srcEid, 2, sender),
            oapp,
            payload2
        );
        IMessagingChannel(channel).verify(
            Origin(srcEid, 1, sender),
            oapp,
            payload1
        );
        
        // 2. Nonce skipping attack
        // Skip nonces to prevent message delivery
        for (uint64 i = 1; i <= 10; i++) {
            IMessagingChannel(channel).skip(
                oapp,
                srcEid,
                sender,
                i
            );
        }
        
        // 3. Race condition attack
        // Race between verification and execution
        bytes32 guid = bytes32(0);
        bytes memory message = "race condition";
        bytes memory extraData = "";
        
        // Verify and execute in parallel
        IMessagingChannel(channel).verify(
            Origin(srcEid, 1, sender),
            oapp,
            keccak256(abi.encodePacked(guid, message))
        );
        ILayerZeroEndpointV2(channel).lzReceive(
            Origin(srcEid, 1, sender),
            oapp,
            guid,
            message,
            extraData
        );
    }
}
```

### Recommended Mitigation
1. Implement strict message ordering:
```solidity
contract MessagingChannel {
    struct MessageQueue {
        uint64 expectedNonce;
        mapping(uint64 => bytes32) verifiedPayloads;
        mapping(uint64 => bool) isExecuted;
    }
    
    mapping(address => mapping(uint32 => mapping(bytes32 => MessageQueue))) private messageQueues;
    
    function _inbound(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce,
        bytes32 _payloadHash
    ) internal {
        MessageQueue storage queue = messageQueues[_receiver][_srcEid][_sender];
        
        // Ensure messages are verified in order
        require(_nonce == queue.expectedNonce, "Invalid nonce order");
        require(_payloadHash != EMPTY_PAYLOAD_HASH, "Invalid payload hash");
        
        // Store verified payload
        queue.verifiedPayloads[_nonce] = _payloadHash;
        queue.expectedNonce = _nonce + 1;
        
        emit MessageVerified(_receiver, _srcEid, _sender, _nonce, _payloadHash);
    }
}
```

2. Enhance nonce management:
```solidity
contract MessagingChannel {
    uint256 public constant MAX_SKIP_NONCE = 100;
    
    function skip(
        address _oapp,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce
    ) external {
        _assertAuthorized(_oapp);
        
        MessageQueue storage queue = messageQueues[_oapp][_srcEid][_sender];
        
        // Validate nonce skipping
        require(
            _nonce == queue.expectedNonce,
            "Invalid nonce"
        );
        require(
            _nonce - queue.lastExecutedNonce <= MAX_SKIP_NONCE,
            "Too many skips"
        );
        
        // Skip nonce with event
        queue.expectedNonce = _nonce + 1;
        queue.skippedNonces[_nonce] = true;
        
        emit NonceSkipped(_oapp, _srcEid, _sender, _nonce);
    }
}
```

3. Add message state validation:
```solidity
contract MessagingChannel {
    enum MessageState { Unknown, Verified, Executed, Skipped }
    
    function getMessageState(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce
    ) public view returns (MessageState) {
        MessageQueue storage queue = messageQueues[_receiver][_srcEid][_sender];
        
        if (queue.skippedNonces[_nonce]) {
            return MessageState.Skipped;
        }
        if (queue.isExecuted[_nonce]) {
            return MessageState.Executed;
        }
        if (queue.verifiedPayloads[_nonce] != bytes32(0)) {
            return MessageState.Verified;
        }
        return MessageState.Unknown;
    }
    
    function _clearPayload(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce,
        bytes memory _payload
    ) internal returns (bytes32) {
        MessageQueue storage queue = messageQueues[_receiver][_srcEid][_sender];
        
        // Validate message state
        MessageState state = getMessageState(
            _receiver,
            _srcEid,
            _sender,
            _nonce
        );
        require(state == MessageState.Verified, "Invalid message state");
        
        // Verify payload hash
        bytes32 actualHash = keccak256(_payload);
        require(
            queue.verifiedPayloads[_nonce] == actualHash,
            "Invalid payload"
        );
        
        // Mark as executed
        queue.isExecuted[_nonce] = true;
        delete queue.verifiedPayloads[_nonce];
        
        return actualHash;
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-10] Messaging Channel Nonce Management and Message Verification Vulnerabilities

### Description
The `MessagingChannel.sol` contract's nonce management and message verification system has several potential vulnerabilities related to message ordering, nonce skipping, and payload verification. The current implementation allows for complex message state transitions that could lead to security issues.

```solidity
contract MessagingChannel {
    mapping(address receiver => mapping(uint32 srcEid => mapping(bytes32 sender => uint64 nonce)))
        public lazyInboundNonce;
    mapping(address receiver => mapping(uint32 srcEid => mapping(bytes32 sender => mapping(uint64 inboundNonce => bytes32 payloadHash))))
        public inboundPayloadHash;
    
    function _inbound(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce,
        bytes32 _payloadHash
    ) internal {
        // No strict ordering enforcement
        if (_payloadHash == EMPTY_PAYLOAD_HASH) revert Errors.LZ_InvalidPayloadHash();
        inboundPayloadHash[_receiver][_srcEid][_sender][_nonce] = _payloadHash;
    }
    
    function skip(address _oapp, uint32 _srcEid, bytes32 _sender, uint64 _nonce) external {
        // Potential for nonce manipulation
        if (_nonce != inboundNonce(_oapp, _srcEid, _sender) + 1) revert Errors.LZ_InvalidNonce(_nonce);
        lazyInboundNonce[_oapp][_srcEid][_sender] = _nonce;
    }
}
```

Key issues:
1. Unordered message verification
2. Nonce skipping vulnerabilities
3. Lazy nonce updates
4. Message reordering possibilities
5. Insufficient payload verification

### Impact
- Messages can be verified out of order
- Potential for nonce manipulation
- Race conditions in message processing
- Possible message reordering attacks
- Inconsistent message states

### Proof of Concept
```solidity
contract MessagingChannelExploit {
    function demonstrateIssues(
        address channel,
        address oapp,
        uint32 srcEid,
        bytes32 sender
    ) external {
        // 1. Message ordering attack
        // Verify messages out of order
        bytes32 payload1 = keccak256("message1");
        bytes32 payload2 = keccak256("message2");
        
        // Verify nonce 2 before nonce 1
        IMessagingChannel(channel).verify(
            Origin(srcEid, 2, sender),
            oapp,
            payload2
        );
        IMessagingChannel(channel).verify(
            Origin(srcEid, 1, sender),
            oapp,
            payload1
        );
        
        // 2. Nonce skipping attack
        // Skip nonces to prevent message delivery
        for (uint64 i = 1; i <= 10; i++) {
            IMessagingChannel(channel).skip(
                oapp,
                srcEid,
                sender,
                i
            );
        }
        
        // 3. Race condition attack
        // Race between verification and execution
        bytes32 guid = bytes32(0);
        bytes memory message = "race condition";
        bytes memory extraData = "";
        
        // Verify and execute in parallel
        IMessagingChannel(channel).verify(
            Origin(srcEid, 1, sender),
            oapp,
            keccak256(abi.encodePacked(guid, message))
        );
        ILayerZeroEndpointV2(channel).lzReceive(
            Origin(srcEid, 1, sender),
            oapp,
            guid,
            message,
            extraData
        );
    }
}
```

### Recommended Mitigation
1. Implement strict message ordering:
```solidity
contract MessagingChannel {
    struct MessageQueue {
        uint64 expectedNonce;
        mapping(uint64 => bytes32) verifiedPayloads;
        mapping(uint64 => bool) isExecuted;
    }
    
    mapping(address => mapping(uint32 => mapping(bytes32 => MessageQueue))) private messageQueues;
    
    function _inbound(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce,
        bytes32 _payloadHash
    ) internal {
        MessageQueue storage queue = messageQueues[_receiver][_srcEid][_sender];
        
        // Ensure messages are verified in order
        require(_nonce == queue.expectedNonce, "Invalid nonce order");
        require(_payloadHash != EMPTY_PAYLOAD_HASH, "Invalid payload hash");
        
        // Store verified payload
        queue.verifiedPayloads[_nonce] = _payloadHash;
        queue.expectedNonce = _nonce + 1;
        
        emit MessageVerified(_receiver, _srcEid, _sender, _nonce, _payloadHash);
    }
}
```

2. Enhance nonce management:
```solidity
contract MessagingChannel {
    uint256 public constant MAX_SKIP_NONCE = 100;
    
    function skip(
        address _oapp,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce
    ) external {
        _assertAuthorized(_oapp);
        
        MessageQueue storage queue = messageQueues[_oapp][_srcEid][_sender];
        
        // Validate nonce skipping
        require(
            _nonce == queue.expectedNonce,
            "Invalid nonce"
        );
        require(
            _nonce - queue.lastExecutedNonce <= MAX_SKIP_NONCE,
            "Too many skips"
        );
        
        // Skip nonce with event
        queue.expectedNonce = _nonce + 1;
        queue.skippedNonces[_nonce] = true;
        
        emit NonceSkipped(_oapp, _srcEid, _sender, _nonce);
    }
}
```

3. Add message state validation:
```solidity
contract MessagingChannel {
    enum MessageState { Unknown, Verified, Executed, Skipped }
    
    function getMessageState(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce
    ) public view returns (MessageState) {
        MessageQueue storage queue = messageQueues[_receiver][_srcEid][_sender];
        
        if (queue.skippedNonces[_nonce]) {
            return MessageState.Skipped;
        }
        if (queue.isExecuted[_nonce]) {
            return MessageState.Executed;
        }
        if (queue.verifiedPayloads[_nonce] != bytes32(0)) {
            return MessageState.Verified;
        }
        return MessageState.Unknown;
    }
    
    function _clearPayload(
        address _receiver,
        uint32 _srcEid,
        bytes32 _sender,
        uint64 _nonce,
        bytes memory _payload
    ) internal returns (bytes32) {
        MessageQueue storage queue = messageQueues[_receiver][_srcEid][_sender];
        
        // Validate message state
        MessageState state = getMessageState(
            _receiver,
            _srcEid,
            _sender,
            _nonce
        );
        require(state == MessageState.Verified, "Invalid message state");
        
        // Verify payload hash
        bytes32 actualHash = keccak256(_payload);
        require(
            queue.verifiedPayloads[_nonce] == actualHash,
            "Invalid payload"
        );
        
        // Mark as executed
        queue.isExecuted[_nonce] = true;
        delete queue.verifiedPayloads[_nonce];
        
        return actualHash;
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-11] Message Composition and Delivery Vulnerabilities

### Description
The `MessagingComposer.sol` contract's message composition and delivery system has several potential vulnerabilities related to message queuing, composition validation, and delivery guarantees. The current implementation allows for potential race conditions and message manipulation.

```solidity
contract MessagingComposer {
    bytes32 private constant NO_MESSAGE_HASH = bytes32(0);
    bytes32 private constant RECEIVED_MESSAGE_HASH = bytes32(uint256(1));
    
    mapping(address from => mapping(address to => mapping(bytes32 guid => mapping(uint16 index => bytes32 messageHash))))
        public composeQueue;
    
    function sendCompose(address _to, bytes32 _guid, uint16 _index, bytes calldata _message) external {
        // No size limits on message
        // No validation of _to address
        if (composeQueue[msg.sender][_to][_guid][_index] != NO_MESSAGE_HASH) revert Errors.LZ_ComposeExists();
        composeQueue[msg.sender][_to][_guid][_index] = keccak256(_message);
    }
    
    function lzCompose(
        address _from,
        address _to,
        bytes32 _guid,
        uint16 _index,
        bytes calldata _message,
        bytes calldata _extraData
    ) external payable {
        // Potential reentrancy before state update
        bytes32 expectedHash = composeQueue[_from][_to][_guid][_index];
        bytes32 actualHash = keccak256(_message);
        if (expectedHash != actualHash) revert Errors.LZ_ComposeNotFound(expectedHash, actualHash);
        
        composeQueue[_from][_to][_guid][_index] = RECEIVED_MESSAGE_HASH;
        ILayerZeroComposer(_to).lzCompose{ value: msg.value }(_from, _guid, _message, msg.sender, _extraData);
    }
}
```

Key issues:
1. No message size limits
2. Insufficient address validation
3. Potential reentrancy vulnerabilities
4. Missing message expiry mechanism
5. Weak composition validation

### Impact
- Potential DoS through large messages
- Message composition manipulation
- Race conditions in delivery
- Possible reentrancy attacks
- Resource exhaustion risks

### Proof of Concept
```solidity
contract MessagingComposerExploit {
    function demonstrateIssues(
        address composer,
        address to,
        bytes32 guid
    ) external {
        // 1. Message size attack
        // Create a very large message to cause DoS
        bytes memory largeMessage = new bytes(1e6);  // 1MB message
        IMessagingComposer(composer).sendCompose(
            to,
            guid,
            0,
            largeMessage
        );
        
        // 2. Reentrancy attack
        // Create a malicious composer that reenters
        MaliciousComposer malicious = new MaliciousComposer();
        bytes memory message = "reentrant";
        IMessagingComposer(composer).sendCompose(
            address(malicious),
            guid,
            1,
            message
        );
        
        // 3. Race condition attack
        // Front-run message delivery
        bytes memory message1 = "race1";
        bytes memory message2 = "race2";
        IMessagingComposer(composer).sendCompose(
            to,
            guid,
            2,
            message1
        );
        IMessagingComposer(composer).lzCompose(
            address(this),
            to,
            guid,
            2,
            message2,
            ""
        );
    }
}

contract MaliciousComposer {
    function lzCompose(
        address _from,
        bytes32 _guid,
        bytes calldata _message,
        address _executor,
        bytes calldata _extraData
    ) external payable {
        // Reenter the original composer
        IMessagingComposer(msg.sender).lzCompose(
            _from,
            address(this),
            _guid,
            0,
            _message,
            ""
        );
    }
}
```

### Recommended Mitigation
1. Implement message size and validation checks:
```solidity
contract MessagingComposer {
    uint256 public constant MAX_MESSAGE_SIZE = 100_000;  // 100KB
    uint256 public constant MAX_EXTRA_DATA_SIZE = 10_000;  // 10KB
    
    function sendCompose(
        address _to,
        bytes32 _guid,
        uint16 _index,
        bytes calldata _message
    ) external {
        // Validate message size
        require(_message.length <= MAX_MESSAGE_SIZE, "Message too large");
        
        // Validate target address
        require(_to != address(0), "Invalid target");
        require(_to != address(this), "Invalid target");
        
        // Check existing message
        if (composeQueue[msg.sender][_to][_guid][_index] != NO_MESSAGE_HASH) {
            revert Errors.LZ_ComposeExists();
        }
        
        // Store message hash
        composeQueue[msg.sender][_to][_guid][_index] = keccak256(_message);
        
        emit ComposeSent(msg.sender, _to, _guid, _index, _message);
    }
}
```

2. Add message expiry and cleanup:
```solidity
contract MessagingComposer {
    struct ComposedMessage {
        bytes32 messageHash;
        uint256 timestamp;
        bool isDelivered;
    }
    
    mapping(address => mapping(address => mapping(bytes32 => mapping(uint16 => ComposedMessage))))
        public composeQueue;
    
    uint256 public constant MESSAGE_EXPIRY = 7 days;
    
    function sendCompose(
        address _to,
        bytes32 _guid,
        uint16 _index,
        bytes calldata _message
    ) external {
        ComposedMessage storage msg = composeQueue[msg.sender][_to][_guid][_index];
        require(
            msg.messageHash == NO_MESSAGE_HASH ||
            block.timestamp <= msg.timestamp + MESSAGE_EXPIRY,
            "Message exists or not expired"
        );
        
        msg.messageHash = keccak256(_message);
        msg.timestamp = block.timestamp;
        msg.isDelivered = false;
        
        emit ComposeSent(msg.sender, _to, _guid, _index, _message);
    }
    
    function cleanupExpiredMessages(
        address _from,
        address _to,
        bytes32 _guid,
        uint16[] calldata _indices
    ) external {
        for (uint256 i = 0; i < _indices.length; i++) {
            ComposedMessage storage msg = composeQueue[_from][_to][_guid][_indices[i]];
            if (
                !msg.isDelivered &&
                block.timestamp > msg.timestamp + MESSAGE_EXPIRY
            ) {
                delete composeQueue[_from][_to][_guid][_indices[i]];
                emit MessageExpired(_from, _to, _guid, _indices[i]);
            }
        }
    }
}
```

3. Enhance delivery security:
```solidity
contract MessagingComposer {
    using ReentrancyGuard for bool;
    
    bool private locked;
    
    function lzCompose(
        address _from,
        address _to,
        bytes32 _guid,
        uint16 _index,
        bytes calldata _message,
        bytes calldata _extraData
    ) external payable nonReentrant {
        // Validate message size
        require(_message.length <= MAX_MESSAGE_SIZE, "Message too large");
        require(_extraData.length <= MAX_EXTRA_DATA_SIZE, "ExtraData too large");
        
        // Get message info
        ComposedMessage storage msg = composeQueue[_from][_to][_guid][_index];
        require(!msg.isDelivered, "Already delivered");
        require(
            block.timestamp <= msg.timestamp + MESSAGE_EXPIRY,
            "Message expired"
        );
        
        // Verify message hash
        bytes32 actualHash = keccak256(_message);
        require(msg.messageHash == actualHash, "Invalid message");
        
        // Mark as delivered before external call
        msg.isDelivered = true;
        
        // Make external call
        try ILayerZeroComposer(_to).lzCompose{ value: msg.value }(
            _from,
            _guid,
            _message,
            msg.sender,
            _extraData
        ) {
            emit ComposeDelivered(_from, _to, _guid, _index);
        } catch (bytes memory reason) {
            // Revert delivery status on failure
            msg.isDelivered = false;
            emit LzComposeAlert(
                _from,
                _to,
                msg.sender,
                _guid,
                _index,
                gasleft(),
                msg.value,
                _message,
                _extraData,
                reason
            );
            revert(string(reason));
        }
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified 

## [M-12] Alternative Endpoint and Upgradeable View Implementation Vulnerabilities

### Description
The `EndpointV2Alt.sol` and `EndpointV2ViewUpgradeable.sol` contracts contain several potential security issues related to token handling and upgrade patterns:

1. In `EndpointV2Alt.sol`:
```solidity
function _payNative(
    uint256 _required,
    uint256 _supplied,
    address _receiver,
    address _refundAddress
) internal override {
    if (msg.value > 0) revert LZ_OnlyAltToken();
    _payToken(nativeErc20, _required, _supplied, _receiver, _refundAddress);
}
```
- No validation of `nativeErc20` token behavior
- Potential issues with non-standard ERC20 tokens
- Immutable token address could be problematic if token is compromised

2. In `EndpointV2ViewUpgradeable.sol`:
```solidity
function executable(Origin memory _origin, address _receiver) public view returns (ExecutionState) {
    bytes32 payloadHash = endpoint.inboundPayloadHash(_receiver, _origin.srcEid, _origin.sender, _origin.nonce);
    // ... state checks ...
    if (payloadHash != EMPTY_PAYLOAD_HASH && payloadHash != NIL_PAYLOAD_HASH) {
        return ExecutionState.VerifiedButNotExecutable;
    }
}
```
- Complex state management could lead to stuck messages
- No timeout mechanism for state transitions
- Potential for inconsistent views across upgrades

### Impact
- Potential for locked funds in alternative endpoint
- Message execution state could become inconsistent
- Upgrade process could break view functionality
- Token-related operations might fail with non-standard tokens

### Proof of Concept
```solidity
contract EndpointAltExploit {
    function demonstrateIssues(address endpoint, address maliciousToken) external {
        EndpointV2Alt alt = EndpointV2Alt(endpoint);
        
        // 1. Deploy malicious ERC20 token
        MaliciousERC20 token = MaliciousERC20(maliciousToken);
        
        // 2. Token could revert on specific addresses
        token.setRevertOnTransfer(endpoint, true);
        
        // 3. Messages would fail to process
        // No way to change token once set
        // Funds could get locked
        
        // 4. State manipulation
        Origin memory origin = Origin({
            srcEid: 1,
            sender: address(this),
            nonce: 1
        });
        
        // 5. View could show incorrect state
        EndpointV2ViewUpgradeable view = EndpointV2ViewUpgradeable(endpoint);
        ExecutionState state = view.executable(origin, address(this));
        // State could be incorrect after upgrade
    }
}

contract MaliciousERC20 {
    mapping(address => bool) public revertOnTransfer;
    
    function transfer(address to, uint256 amount) external returns (bool) {
        if (revertOnTransfer[to]) revert("Malicious revert");
        return true;
    }
    
    function setRevertOnTransfer(address target, bool shouldRevert) external {
        revertOnTransfer[target] = shouldRevert;
    }
}
```

### Recommended Mitigation
1. Add token validation and fallback mechanisms:
```solidity
contract EndpointV2Alt {
    address public immutable backupToken;
    
    constructor(uint32 _eid, address _owner, address _altToken, address _backupToken) {
        require(_altToken.code.length > 0, "Invalid token");
        require(_backupToken.code.length > 0, "Invalid backup");
        nativeErc20 = _altToken;
        backupToken = _backupToken;
    }
    
    function _payNative(
        uint256 _required,
        uint256 _supplied,
        address _receiver,
        address _refundAddress
    ) internal override {
        if (msg.value > 0) revert LZ_OnlyAltToken();
        
        try _payToken(nativeErc20, _required, _supplied, _receiver, _refundAddress) {
            // Success case
        } catch {
            // Fallback to backup token
            _payToken(backupToken, _required, _supplied, _receiver, _refundAddress);
        }
    }
}
```

2. Enhance state management:
```solidity
contract EndpointV2ViewUpgradeable {
    uint256 public constant MAX_STATE_AGE = 7 days;
    
    struct ExecutionStateInfo {
        ExecutionState state;
        uint256 timestamp;
        uint256 version;
    }
    
    mapping(bytes32 => ExecutionStateInfo) public executionStates;
    
    function executable(
        Origin memory _origin,
        address _receiver
    ) public returns (ExecutionState) {
        bytes32 msgHash = keccak256(abi.encode(_origin, _receiver));
        ExecutionStateInfo storage info = executionStates[msgHash];
        
        // Check state age
        if (block.timestamp > info.timestamp + MAX_STATE_AGE) {
            info.state = ExecutionState.NotExecutable;
        }
        
        // Update state
        ExecutionState newState = _calculateState(_origin, _receiver);
        if (newState != info.state) {
            info.state = newState;
            info.timestamp = block.timestamp;
            info.version = getVersion();
        }
        
        return info.state;
    }
}
```

3. Implement upgrade safety:
```solidity
contract EndpointV2ViewUpgradeable {
    uint256 public version;
    mapping(uint256 => mapping(bytes32 => bool)) public deprecatedStates;
    
    function upgrade() external onlyOwner {
        version++;
        // Mark states as deprecated
        emit VersionUpgraded(version);
    }
    
    function executable(
        Origin memory _origin,
        address _receiver
    ) public view returns (ExecutionState) {
        bytes32 msgHash = keccak256(abi.encode(_origin, _receiver));
        
        // Check if state was deprecated in upgrade
        if (deprecatedStates[version][msgHash]) {
            return ExecutionState.NotExecutable;
        }
        
        // Rest of function
    }
}
```

### Status
- [ ] Reported
- [ ] Acknowledged
- [ ] Fixed
- [ ] Verified