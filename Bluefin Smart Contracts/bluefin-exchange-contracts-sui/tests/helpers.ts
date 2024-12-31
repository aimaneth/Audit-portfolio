import { expect } from 'chai';
import { getSignerFromSeed, TEST_WALLETS } from '../submodules/library-sui';

// Mock types to avoid @mysten/sui.js dependency issues
type JsonRpcProvider = any;
type SuiTransactionBlockResponse = any;

// Setup provider
export const provider = {} as JsonRpcProvider;

// Setup owner signer
export const ownerSigner = getSignerFromSeed(TEST_WALLETS[0].phrase, provider);

// Mock coin ID for tests
export const victimCoinId = '0x1234'; // Replace with actual test coin ID

// Test utilities
export const expectTxToSucceed = async (tx: SuiTransactionBlockResponse) => {
    expect(tx.status).to.equal('success');
};

export const expectTxToFail = async (tx: SuiTransactionBlockResponse) => {
    expect(tx.status).to.equal('failure');
};

// Fund test accounts with initial balance
export const fundTestAccounts = async () => {
    // Implementation depends on test environment setup
    // This is a placeholder that should be implemented based on your test requirements
    return Promise.resolve();
};

export { expect }; 