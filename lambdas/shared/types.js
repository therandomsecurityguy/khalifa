"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Logger = void 0;
exports.getSecret = getSecret;
class Logger {
    constructor(context) {
        this.context = context;
    }
    info(message, meta) {
        console.log(JSON.stringify({
            timestamp: new Date().toISOString(),
            level: 'INFO',
            context: this.context,
            message,
            ...meta,
        }));
    }
    error(message, meta) {
        console.error(JSON.stringify({
            timestamp: new Date().toISOString(),
            level: 'ERROR',
            context: this.context,
            message,
            ...meta,
        }));
    }
    warn(message, meta) {
        console.warn(JSON.stringify({
            timestamp: new Date().toISOString(),
            level: 'WARN',
            context: this.context,
            message,
            ...meta,
        }));
    }
}
exports.Logger = Logger;
async function getSecret(secretArn) {
    return { username: 'user', password: 'pass' };
}
//# sourceMappingURL=types.js.map