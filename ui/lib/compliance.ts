export const FRAMEWORKS: Record<string, { label: string; description: string }> = {
  CIS_AWS_FOUNDATIONS: {
    label: 'CIS AWS Foundations v3.0',
    description: 'CIS Amazon Web Services Foundations Benchmark v3.0.0',
  },
  KHALIFA_BASELINE: {
    label: 'Khalifa Baseline',
    description:
      'Checks beyond the CIS benchmark: container vulnerabilities, attack paths, Secrets Manager, Kubernetes exposure and credential tripwires',
  },
};

export function frameworkLabel(id: string): string {
  return FRAMEWORKS[id]?.label ?? id;
}
