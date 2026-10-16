import { runOnce } from './run-once';

export const handler = async (): Promise<unknown> => {
  return runOnce(process.env.NEPTUNE_ENDPOINT || '');
};
