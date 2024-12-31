import {
    DeploymentConfigs,
    getProvider,
    getSignerFromSeed,
    OnChainCalls,
    Transaction,
    TEST_WALLETS,
    toBigNumberStr,
    ERROR_CODES,
    packageName
} from "../bluefin-exchange-contracts-sui/submodules/library-sui";
import { postDeployment, publishPackage } from "../bluefin-exchange-contracts-sui/src/helpers";
import {
    fundTestAccounts,
    expectTxToSucceed,
    expect
} from "../bluefin-exchange-contracts-sui/tests/helpers";

describe("Liquidation Fairness Tests", () => {
    let onChain: OnChainCalls;
    let liquidator = getSignerFromSeed(TEST_WALLETS[0].phrase, provider);
    let victim = getSignerFromSeed(TEST_WALLETS[1].phrase, provider);
    
    beforeEach(async () => {
        // Setup
        const publishTxn = await publishPackage(false, ownerSigner, packageName);
        const objects = await getGenesisMap(provider, publishTxn);
        let deploymentData = packDeploymentData(await ownerSigner.getAddress(), objects);
        onChain = new OnChainCalls(ownerSigner, deploymentData);
        await fundTestAccounts();
    });

    it("should demonstrate unfair micro-liquidation", async () => {
        // 1. Setup large position for victim
        const collateral = toBigNumberStr(100000, 6); // $100k collateral
        await onChain.depositToBank({
            coinID: victimCoinId,
            amount: collateral
        }, victim);
        
        // Open large leveraged position
        await onChain.openPosition({
            size: toBigNumberStr(1000, 6),    // 1000 tokens
            leverage: 2,                       // 2x leverage
            price: toBigNumberStr(100, 6)      // $100 per token
        }, victim);
        
        // 2. Move price to just above liquidation threshold
        await onChain.updateOraclePrice({
            price: toBigNumberStr(90, 6)  // Drop 10%
        });
        
        // 3. Liquidator performs micro-liquidation
        const microAmount = toBigNumberStr(0.0001, 6); // Tiny liquidation amount
        const liquidationTx = await onChain.liquidate({
            account: victim.address(),
            amount: microAmount
        }, liquidator);
        
        // 4. Verify micro-liquidation succeeded
        expectTxToSucceed(liquidationTx);
        
        // 5. Check liquidation fee is disproportionate to liquidation size
        const liquidationEvent = Transaction.getEvents(liquidationTx, "LiquidationEvent")[0];
        const liquidationFee = liquidationEvent.fee;
        const liquidationSize = liquidationEvent.amount;
        
        // Fee should be unreasonably high compared to liquidation size
        expect(Number(liquidationFee) / Number(liquidationSize)).to.be.greaterThan(0.1); // Fee > 10% of liquidation
    });

    it("should demonstrate MEV sandwich on liquidation", async () => {
        // 1. Setup position near liquidation
        await onChain.depositToBank({
            coinID: victimCoinId,
            amount: toBigNumberStr(1000, 6)
        }, victim);
        
        await onChain.openPosition({
            size: toBigNumberStr(10, 6),
            leverage: 5,
            price: toBigNumberStr(100, 6)
        }, victim);
        
        // 2. MEV bot front-runs with price update
        await onChain.updateOraclePrice({
            price: toBigNumberStr(85, 6)  // Drop to liquidation level
        }, liquidator);
        
        // 3. Execute liquidation
        const liquidationTx = await onChain.liquidate({
            account: victim.address()
        }, liquidator);
        
        // 4. Back-run with price recovery
        await onChain.updateOraclePrice({
            price: toBigNumberStr(95, 6)  // Price recovers
        }, liquidator);
        
        // 5. Verify MEV profit
        const liquidatorBalance = await onChain.getBalance(liquidator.address());
        expect(liquidatorBalance).to.be.greaterThan(initialLiquidatorBalance);
    });
}); 