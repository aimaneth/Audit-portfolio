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

describe("Decimal Precision Loss Tests", () => {
    let onChain: OnChainCalls;
    let user = getSignerFromSeed(TEST_WALLETS[0].phrase, provider);
    
    beforeEach(async () => {
        // Setup
        const publishTxn = await publishPackage(false, ownerSigner, packageName);
        const objects = await getGenesisMap(provider, publishTxn);
        let deploymentData = packDeploymentData(await ownerSigner.getAddress(), objects);
        onChain = new OnChainCalls(ownerSigner, deploymentData);
        await fundTestAccounts();
    });

    it("should demonstrate precision loss in withdraw_all_margin_from_bank", async () => {
        // 1. Deposit an amount that will cause precision loss
        const depositAmount = toBigNumberStr("1000.123456", 6); // 6 decimal places
        await onChain.depositToBank({
            coinID: userCoinId,
            amount: depositAmount
        }, user);
        
        // Get initial balance
        const initialBalance = await onChain.getBankBalance(user.address());
        expect(initialBalance).to.equal(depositAmount);
        
        // 2. Withdraw all margin
        const withdrawTx = await onChain.withdrawAllMarginFromBank(user);
        expectTxToSucceed(withdrawTx);
        
        // 3. Check final balance
        const finalBalance = await onChain.getBankBalance(user.address());
        expect(finalBalance).to.equal("0");
        
        // 4. Check actual withdrawn amount from events
        const withdrawEvent = Transaction.getEvents(withdrawTx, "BankBalanceUpdate")[0];
        const withdrawnAmount = withdrawEvent.amount;
        
        // Due to division by 1000 and back multiplication, we should see precision loss
        expect(withdrawnAmount).to.not.equal(depositAmount);
        
        // Calculate the dust left due to precision loss
        const dust = Number(depositAmount) - Number(withdrawnAmount);
        expect(dust).to.not.equal(0);
    });

    it("should demonstrate cumulative precision loss with multiple operations", async () => {
        // 1. Perform multiple small deposits
        const smallAmount = toBigNumberStr("0.123456", 6);
        for(let i = 0; i < 10; i++) {
            await onChain.depositToBank({
                coinID: userCoinId,
                amount: smallAmount
            }, user);
        }
        
        // Expected total: 1.23456
        const expectedTotal = toBigNumberStr("1.23456", 6);
        
        // 2. Check actual balance
        const actualBalance = await onChain.getBankBalance(user.address());
        
        // 3. Verify precision loss
        expect(actualBalance).to.not.equal(expectedTotal);
        
        // 4. Withdraw all and check dust
        const withdrawTx = await onChain.withdrawAllMarginFromBank(user);
        const withdrawEvent = Transaction.getEvents(withdrawTx, "BankBalanceUpdate")[0];
        
        // Calculate total precision loss
        const totalDust = Number(expectedTotal) - Number(withdrawEvent.amount);
        expect(totalDust).to.be.greaterThan(0);
    });
}); 