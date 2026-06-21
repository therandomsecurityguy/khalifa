"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getSecret = getSecret;
const client_secrets_manager_1 = require("@aws-sdk/client-secrets-manager");
const smClient = new client_secrets_manager_1.SecretsManagerClient({ region: 'us-east-1' });
async function getSecret(secretArn) {
    const command = new client_secrets_manager_1.GetSecretValueCommand({ SecretId: secretArn });
    const response = await smClient.send(command);
    return JSON.parse(response.SecretString || '{}');
}
//# sourceMappingURL=secrets-client.js.map