// Mock types to avoid @mysten/sui.js dependency issues
type SuiTransactionBlockResponse = any;

export async function publishPackage(
    isDryRun: boolean,
    signer: any,
    packageName: string
): Promise<SuiTransactionBlockResponse> {
    // Mock implementation
    return {} as SuiTransactionBlockResponse;
}

export async function postDeployment(
    signer: any,
    deploymentData: any,
    coinPackageId: string
): Promise<any> {
    // Mock implementation
    return {};
} 