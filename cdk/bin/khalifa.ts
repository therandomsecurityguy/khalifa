#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SecurityGraphIngestionStack } from '../lib/khalifa-stack';

const app = new cdk.App();

const parseList = (value: string | undefined) =>
  (value || '')
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
const required = (name: string) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const accountIds = parseList(process.env.COLLECTION_ACCOUNT_IDS);
const parentIds = parseList(process.env.COLLECTION_PARENT_IDS);
if (accountIds.length === 0 && parentIds.length === 0) {
  throw new Error('COLLECTION_ACCOUNT_IDS or COLLECTION_PARENT_IDS is required');
}
const neptuneClusterResourceId = process.env.NEPTUNE_CLUSTER_RESOURCE_ID;
if (!neptuneClusterResourceId) throw new Error('NEPTUNE_CLUSTER_RESOURCE_ID is required');
const region = process.env.AWS_REGION || 'us-east-1';
const homeAccountId = required('HOME_ACCOUNT_ID');
if (!/^\d{12}$/.test(homeAccountId))
  throw new Error('HOME_ACCOUNT_ID must be a 12-digit account ID');

new SecurityGraphIngestionStack(app, 'SecurityGraphIngestionStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region,
  },
  description: 'Security Graph Ingestion Pipeline',
  neptuneEndpoint: process.env.NEPTUNE_ENDPOINT || `neptune-cluster.${region}.amazonaws.com`,
  neptuneClusterResourceId,
  homeAccountId,
  accountIds,
  parentIds,
  collectionRegions: parseList(process.env.COLLECTION_REGIONS || region),
  enableCanaries: process.env.ENABLE_CANARIES === 'true',
  scannerVpcId: process.env.SCANNER_VPC_ID,
  scannerPrivateSubnetIds: parseList(process.env.SCANNER_PRIVATE_SUBNET_IDS),
  scannerAvailabilityZones: parseList(process.env.SCANNER_AVAILABILITY_ZONES),
  scannerSecurityGroupId: process.env.SCANNER_SECURITY_GROUP_ID,
  enableDspmEventTrigger: process.env.ENABLE_DSPM_EVENT_TRIGGER === 'true',
  dspmBucketAllowlist: parseList(process.env.DSPM_BUCKET_ALLOWLIST),
});
