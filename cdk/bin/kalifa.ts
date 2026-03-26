#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecurityGraphIngestionStack } from '../lib/kalifa-stack';

const app = new cdk.App();

new SecurityGraphIngestionStack(app, 'SecurityGraphIngestionStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: 'us-east-1',
  },
  description: 'Security Graph Ingestion Pipeline',
  neptuneEndpoint: process.env.NEPTUNE_ENDPOINT || 'neptune-cluster.us-east-1.amazonaws.com',
  masterAccountId: process.env.MASTER_ACCOUNT_ID || '123456789012',
});
