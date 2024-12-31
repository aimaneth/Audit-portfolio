# Contributing Guidelines

Thank you for your interest in contributing to this security research portfolio! This document provides guidelines for contributing vulnerability demonstrations and security findings.

## Adding New Vulnerabilities

### 1. Structure
- Place vulnerable contracts in `src/vulnerabilities/`
- Add exploit tests in `test/vulnerabilities/`
- Include detailed documentation in `docs/findings/`

### 2. Documentation
Each vulnerability should include:
- Clear description of the vulnerability
- Impact assessment
- Proof of Concept
- Recommended fixes
- Test cases

### 3. Code Style
- Follow Solidity style guide
- Include comprehensive comments
- Use meaningful variable names
- Add NatSpec documentation

### 4. Testing
- Write comprehensive test cases
- Include both positive and negative tests
- Document test scenarios
- Ensure all tests pass

## Pull Request Process

1. Create a new branch for your contribution
2. Follow the PR template
3. Ensure all tests pass
4. Update documentation as needed
5. Request review from maintainers

## Code Quality Requirements

### Solidity Code
```solidity
// Example of expected code style
/// @title Vulnerable Contract
/// @notice This contract demonstrates a specific vulnerability
/// @dev Include important development notes
contract VulnerableContract {
    // State variables should be well documented
    uint256 public value;
    
    /// @notice Clear description of function purpose
    /// @param amount The amount to process
    function vulnerableFunction(uint256 amount) external {
        // Implementation
    }
}
```

### Test Code
```solidity
contract VulnerabilityTest is Test {
    function setUp() public {
        // Clear setup
    }
    
    function test_ExploitScenario() public {
        // Clear test steps
    }
}
```

## Questions or Concerns?
Feel free to open an issue for any questions or concerns about contributing. 