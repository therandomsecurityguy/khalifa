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
exports.RiskRuleRunner = void 0;
exports.resolveStaleIssues = resolveStaleIssues;
const client_dynamodb_1 = require("@aws-sdk/client-dynamodb");
const lib_dynamodb_1 = require("@aws-sdk/lib-dynamodb");
const util_dynamodb_1 = require("@aws-sdk/util-dynamodb");
const rules_1 = require("./rules");
const scoring_1 = require("./scoring");
const MAX_PAGINATION_BATCH = 100;
const ISSUES_TABLE = process.env.ISSUES_TABLE || 'SecurityIssues';
class GremlinNeptuneClient {
    constructor(endpoint) {
        this.endpoint = endpoint;
    }
    async connect() {
        const Gremlin = await Promise.resolve().then(() => __importStar(require('gremlin')));
        this.client = new Gremlin.driver.DriverRemoteConnection(`wss://${this.endpoint}/gremlin`, {
            traversalSource: 'g',
        });
    }
    async close() {
        if (this.client) {
            await this.client.close();
        }
    }
    async executeQuery(query, bindings = {}) {
        const results = [];
        let hasMore = true;
        while (hasMore) {
            const cursor = await this.client.submit(query, bindings);
            const batch = [];
            // eslint-disable-next-line no-constant-condition
            while (true) {
                const item = await cursor.next();
                if (!item)
                    break;
                batch.push(item);
            }
            results.push(...batch);
            if (batch.length < MAX_PAGINATION_BATCH) {
                hasMore = false;
            }
        }
        return results;
    }
}
class DynamoDBIssueStore {
    constructor() {
        const client = new client_dynamodb_1.DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
        this.docClient = lib_dynamodb_1.DynamoDBDocumentClient.from(client);
    }
    generateIssueId(ruleId, resourceIds) {
        const resourceSet = resourceIds.slice(0, 3).sort().join('|');
        const hash = Buffer.from(`${ruleId}:${resourceSet}`).toString('base64').slice(0, 16);
        return `${ruleId}-${hash}`;
    }
    async getIssue(issueId) {
        const result = await this.docClient.send(new client_dynamodb_1.GetItemCommand({
            TableName: ISSUES_TABLE,
            Key: { id: { S: issueId } },
        }));
        if (!result.Item)
            return null;
        return (0, util_dynamodb_1.unmarshall)(result.Item);
    }
    async getIssueByRuleAndResources(ruleId, resourceIds) {
        const issueId = this.generateIssueId(ruleId, resourceIds);
        return this.getIssue(issueId);
    }
    async upsertIssue(issue) {
        await this.docClient.send(new client_dynamodb_1.PutItemCommand({
            TableName: ISSUES_TABLE,
            Item: (0, util_dynamodb_1.marshall)(issue),
            ConditionExpression: 'attribute_not_exists(id)',
        }));
    }
    async updateIssueStatus(issueId, status) {
        await this.docClient.send(new client_dynamodb_1.UpdateItemCommand({
            TableName: ISSUES_TABLE,
            Key: { id: { S: issueId } },
            UpdateExpression: 'SET #status = :status, updatedAt = :updatedAt',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: {
                ':status': { S: status },
                ':updatedAt': { S: new Date().toISOString() },
            },
        }));
    }
    async getOpenIssuesByRule(ruleId) {
        const result = await this.docClient.send(new client_dynamodb_1.QueryCommand({
            TableName: ISSUES_TABLE,
            IndexName: 'RuleIdIndex',
            KeyConditionExpression: 'ruleId = :ruleId',
            FilterExpression: '#status = :status',
            ExpressionAttributeNames: { '#status': 'status' },
            ExpressionAttributeValues: {
                ':ruleId': { S: ruleId },
                ':status': { S: 'open' },
            },
        }));
        if (!result.Items)
            return [];
        return result.Items.map((item) => (0, util_dynamodb_1.unmarshall)(item));
    }
}
class RiskRuleRunner {
    constructor(neptuneEndpoint) {
        this.neptuneClient = new GremlinNeptuneClient(neptuneEndpoint);
        this.issueStore = new DynamoDBIssueStore();
    }
    async initialize() {
        await this.neptuneClient.connect();
    }
    async shutdown() {
        await this.neptuneClient.close();
    }
    async runRule(rule) {
        const startTime = Date.now();
        const errors = [];
        let issuesCreated = 0;
        let issuesResolved = 0;
        try {
            const results = await this.neptuneClient.executeQuery(rule.gremlinQueryTemplate);
            const activeIssueIds = new Set();
            for (const match of results) {
                const path = this.extractPathFromMatch(match);
                const resources = this.extractResourcesFromPath(path);
                if (resources.length === 0)
                    continue;
                const existingIssue = await this.issueStore.getIssueByRuleAndResources(rule.id, resources.map((r) => r.resourceId));
                if (existingIssue) {
                    activeIssueIds.add(existingIssue.id);
                }
                else {
                    const issue = await this.createIssueFromMatch(rule, path, resources);
                    await this.issueStore.upsertIssue(issue);
                    issuesCreated++;
                    activeIssueIds.add(issue.id);
                }
            }
            const openIssues = await this.issueStore.getOpenIssuesByRule(rule.id);
            for (const issue of openIssues) {
                if (!activeIssueIds.has(issue.id)) {
                    await this.issueStore.updateIssueStatus(issue.id, 'resolved');
                    issuesResolved++;
                }
            }
        }
        catch (error) {
            errors.push(error instanceof Error ? error.message : String(error));
        }
        return {
            ruleId: rule.id,
            executionTime: Date.now() - startTime,
            matches: [],
            issuesCreated,
            issuesResolved,
            errors: errors.length > 0 ? errors : undefined,
        };
    }
    async runAllRules() {
        const rules = (0, rules_1.getEnabledRules)();
        const results = [];
        for (const rule of rules) {
            const result = await this.runRule(rule);
            results.push(result);
        }
        return results;
    }
    extractPathFromMatch(match) {
        if (match.objects) {
            return match.objects.map((obj) => ({
                id: obj.id?.value || obj.id,
                label: obj.label,
                properties: this.extractProperties(obj),
            }));
        }
        if (Array.isArray(match)) {
            return match.map((item) => ({
                id: item?.id?.value || item?.id,
                label: item?.label || 'unknown',
                properties: this.extractProperties(item),
            }));
        }
        return [];
    }
    extractProperties(obj) {
        if (!obj)
            return {};
        const properties = {};
        for (const [key, value] of Object.entries(obj)) {
            if (key !== 'id' && key !== 'label') {
                const val = value;
                properties[key] = val?.value ?? val;
            }
        }
        return properties;
    }
    extractResourcesFromPath(path) {
        return path
            .filter((v) => v.label && !['Internet', 'IAMRole', 'IAMPolicy'].includes(v.label))
            .map((v) => ({
            resourceId: v.id,
            resourceType: v.label,
            resourceName: v.properties?.name || v.properties?.Name,
        }));
    }
    async createIssueFromMatch(rule, path, resources) {
        const now = new Date().toISOString();
        const riskInput = this.buildRiskInput(rule, path, resources);
        const scoreResult = (0, scoring_1.computeRiskScore)(riskInput);
        const pathSegments = path.slice(0, -1).map((from, i) => ({
            from: from.id,
            to: path[i + 1].id,
            edgeType: path[i + 1].label,
        }));
        return {
            id: this.issueStore.generateIssueId(rule.id, resources.map((r) => r.resourceId)),
            ruleId: rule.id,
            resourcesInvolved: resources.map((r) => ({
                resourceId: r.resourceId,
                resourceType: r.resourceType,
                resourceName: r.resourceName,
            })),
            pathSummary: pathSegments,
            riskScore: scoreResult.score,
            severity: scoreResult.severity,
            status: 'open',
            createdAt: now,
            updatedAt: now,
            owningTeam: rule.ownerTeam,
            remediationHint: (0, scoring_1.getRemediationHint)(rule.id, {}),
            metadata: {
                scoringFactors: scoreResult.factors,
                ruleName: rule.name,
            },
        };
    }
    buildRiskInput(rule, path, resources) {
        let exposureLevel = 'internal';
        let dataClassification = 'public';
        let environment = 'dev';
        let isCrownJewel = false;
        const attackPathLength = path.length;
        for (const v of path) {
            if (v.properties?.isInternetExposed === true) {
                exposureLevel = 'internet';
            }
            if (v.properties?.data_classification === 'restricted' ||
                v.properties?.data_classification === 'secret') {
                dataClassification = v.properties.data_classification;
            }
            if (v.properties?.crown_jewel === true) {
                isCrownJewel = true;
            }
            if (v.properties?.env === 'prod') {
                environment = 'prod';
            }
            else if (v.properties?.env === 'staging' && environment !== 'prod') {
                environment = 'staging';
            }
        }
        return {
            exposureLevel,
            dataClassification,
            environment,
            isCrownJewel,
            attackPathLength,
        };
    }
}
exports.RiskRuleRunner = RiskRuleRunner;
async function resolveStaleIssues(neptuneEndpoint) {
    const runner = new RiskRuleRunner(neptuneEndpoint);
    await runner.initialize();
    let resolvedCount = 0;
    try {
        for (const rule of (0, rules_1.getEnabledRules)()) {
            const result = await runner.runRule(rule);
            resolvedCount += result.issuesResolved;
        }
    }
    finally {
        await runner.shutdown();
    }
    return resolvedCount;
}
//# sourceMappingURL=runner.js.map