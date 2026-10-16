import { LambdaClient, ListFunctionsCommand } from '@aws-sdk/client-lambda';
import { appendAll } from '../../shared/arrays';
import type { Classifier, ClassificationMatch, ClassificationResult } from './classifier';
import { aggregateResults } from './s3-sampler';

export interface LambdaScanResult {
  functionArn: string;
  functionName: string;
  result: ClassificationResult | null;
  error?: string;
}

const LIST_PAGE_SIZE = 50;

export async function scanLambdaFunctions(
  lambdaClient: LambdaClient,
  classifiers: Classifier[]
): Promise<LambdaScanResult[]> {
  const results: LambdaScanResult[] = [];
  let marker: string | undefined;

  do {
    const response = await lambdaClient.send(
      new ListFunctionsCommand({ Marker: marker, MaxItems: LIST_PAGE_SIZE })
    );

    for (const fn of response.Functions || []) {
      if (!fn.FunctionArn || !fn.FunctionName) continue;

      try {
        const variables = fn.Environment?.Variables || {};
        const keys = Object.keys(variables);

        if (keys.length === 0) {
          results.push({
            functionArn: fn.FunctionArn,
            functionName: fn.FunctionName,
            result: null,
          });
          continue;
        }

        // Environment values are scanned in memory and never persisted; only
        // aggregated classification counts are written to the graph.
        const content = keys.map((key) => `${key}=${variables[key]}`).join('\n');
        const allMatches: ClassificationMatch[] = [];
        for (const classifier of classifiers) {
          const matches = await classifier.classify(content);
          appendAll(allMatches, matches);
        }

        results.push({
          functionArn: fn.FunctionArn,
          functionName: fn.FunctionName,
          result: aggregateResults(allMatches, keys.length, 0, classifiers),
        });
      } catch (e) {
        results.push({
          functionArn: fn.FunctionArn,
          functionName: fn.FunctionName,
          result: null,
          error: e instanceof Error ? e.message : String(e),
        });
      }
    }

    marker = response.NextMarker;
  } while (marker);

  return results;
}
