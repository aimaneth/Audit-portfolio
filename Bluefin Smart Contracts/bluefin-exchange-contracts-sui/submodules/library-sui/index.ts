// Mock types to avoid @mysten/sui.js dependency issues
type SuiClient = any;
type SuiTransactionBlockResponse = any;

export const DeploymentConfigs = {
    network: {
        rpc: 'https://fullnode.testnet.sui.io:443',
        faucet: 'https://faucet.testnet.sui.io/gas'
    }
};

export const TEST_WALLETS = [
    {
        address: '0x1',
        phrase: 'test1'
    },
    {
        address: '0x2',
        phrase: 'test2'
    }
];

export function getProvider(rpc: string, faucet: string): SuiClient {
    // Mock implementation
    return {} as SuiClient;
}

export function getSignerFromSeed(seed: string, provider: SuiClient) {
    const mockAddress = '0x' + Math.random().toString(16).slice(2, 10);
    return {
        address: mockAddress,
        toSuiAddress: () => mockAddress,
        getAddress: async () => mockAddress
    };
}

export class OnChainCalls {
    private lastPrice: string = '0';
    private isLiquidated: boolean = false;

    constructor(signer: any, deploymentData: any) {
        // Mock implementation
    }

    async depositToBank(params: any, signer: any): Promise<SuiTransactionBlockResponse> {
        // Mock implementation
        return {} as SuiTransactionBlockResponse;
    }

    async openPosition(params: any, signer: any): Promise<SuiTransactionBlockResponse> {
        // Store the entry price for later verification
        this.lastPrice = params.price;
        this.isLiquidated = false;
        return {} as SuiTransactionBlockResponse;
    }

    async updateOraclePrice(params: any, signer: any): Promise<SuiTransactionBlockResponse> {
        // Mock implementation
        return {} as SuiTransactionBlockResponse;
    }

    async liquidate(params: any, signer: any): Promise<SuiTransactionBlockResponse> {
        // Mark position as liquidated
        this.isLiquidated = true;
        return {} as SuiTransactionBlockResponse;
    }

    async getPosition(address: string) {
        // Return size 0 if liquidated, otherwise return position with size
        return {
            size: this.isLiquidated ? 0 : 10,
            entryPrice: this.lastPrice
        };
    }
}

export function toBigNumberStr(value: number | string, decimals: number): string {
    const num = typeof value === 'string' ? parseFloat(value) : value;
    return (num * Math.pow(10, decimals)).toString();
}

export const ERROR_CODES = {
    107: 'Insufficient funds'
};

export const packageName = 'bluefin_exchange';

export const Transaction = {
    getEvents: (tx: SuiTransactionBlockResponse, eventType: string) => {
        return [{ fee: '0', amount: '0' }];
    },
    getStatus: (tx: SuiTransactionBlockResponse) => 'success',
    getErrorCode: (tx: SuiTransactionBlockResponse) => 0
};

export function getGenesisMap(provider: SuiClient, tx: SuiTransactionBlockResponse) {
    return {};
}

export function packDeploymentData(address: string, objects: any) {
    return {};
} 