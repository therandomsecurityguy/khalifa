import { runComplianceOnce } from './run-compliance-once';

export const handler = async (): Promise<unknown> => {
  return runComplianceOnce(process.env.NEPTUNE_ENDPOINT || '');
};
