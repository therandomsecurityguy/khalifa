#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecurityGraphIngestionStack } from '../lib/khalifa-stack';
import { SecurityGraphEksStack } from '../lib/eks-infrastructure';

const app = new cdk.App();

const accountIds = process.env.ACCOUNT_IDS
  ? process.env.ACCOUNT_IDS.split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  : [process.env.MASTER_ACCOUNT_ID || '123456789012'];

const ingestionStack = new SecurityGraphIngestionStack(app, 'SecurityGraphIngestionStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.AWS_REGION || 'us-east-1',
  },
  description: 'Security Graph Ingestion Pipeline',
  neptuneEndpoint: process.env.NEPTUNE_ENDPOINT || 'neptune-cluster.us-east-1.amazonaws.com',
  masterAccountId: process.env.MASTER_ACCOUNT_ID || '123456789012',
  accountIds,
});

if (process.env.DEPLOY_EKS === 'true' && process.env.EKS_VPC_ID) {
  new SecurityGraphEksStack(app, 'SecurityGraphEksStack', {
    env: {
      account: process.env.CDK_DEFAULT_ACCOUNT,
      region: process.env.AWS_REGION || 'us-east-1',
    },
    vpcId: process.env.EKS_VPC_ID,
    neptuneEndpoint: process.env.NEPTUNE_ENDPOINT || 'neptune-cluster.us-east-1.amazonaws.com',
    issuesTableName: ingestionStack.issuesTable.tableName,
    evidenceTableName: ingestionStack.evidenceTable.tableName,
    reportsTableName: ingestionStack.reportsTable.tableName,
    certificateArn: process.env.EKS_CERTIFICATE_ARN || '',
    cognitoUserPoolId: process.env.COGNITO_USER_POOL_ID || '',
    cognitoClientId: process.env.COGNITO_CLIENT_ID || '',
  });
}
