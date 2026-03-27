import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
export interface SecurityGraphIngestionStackProps extends cdk.StackProps {
    neptuneEndpoint: string;
    masterAccountId: string;
}
export declare class SecurityGraphIngestionStack extends cdk.Stack {
    constructor(scope: Construct, id: string, props: SecurityGraphIngestionStackProps);
}
//# sourceMappingURL=khalifa-stack.d.ts.map