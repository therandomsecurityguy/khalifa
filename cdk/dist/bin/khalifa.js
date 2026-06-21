#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
require("source-map-support/register");
const cdk = __importStar(require("aws-cdk-lib"));
const khalifa_stack_1 = require("../lib/khalifa-stack");
const app = new cdk.App();
const accountIds = process.env.ACCOUNT_IDS
    ? process.env.ACCOUNT_IDS.split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : [process.env.MASTER_ACCOUNT_ID || '123456789012'];
new khalifa_stack_1.SecurityGraphIngestionStack(app, 'SecurityGraphIngestionStack', {
    env: {
        account: process.env.CDK_DEFAULT_ACCOUNT,
        region: process.env.AWS_REGION || 'us-east-1',
    },
    description: 'Security Graph Ingestion Pipeline',
    neptuneEndpoint: process.env.NEPTUNE_ENDPOINT || 'neptune-cluster.us-east-1.amazonaws.com',
    masterAccountId: process.env.MASTER_ACCOUNT_ID || '123456789012',
    accountIds,
});
//# sourceMappingURL=khalifa.js.map