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
  SOC2: {
    label: 'SOC 2',
    description:
      'SOC 2 Trust Services Criteria requirements mapped to the controls Khalifa evaluates; nothing here is certified',
  },
  ISO27001: {
    label: 'ISO 27001',
    description:
      'ISO/IEC 27001:2022 Annex A requirements mapped to the controls Khalifa evaluates; nothing here is certified',
  },
  PCI_DSS: {
    label: 'PCI DSS',
    description:
      'PCI DSS v4.0 requirements mapped to the controls Khalifa evaluates; nothing here is certified',
  },
  NIST_800_53: {
    label: 'NIST 800-53',
    description:
      'NIST SP 800-53 Rev. 5 controls mapped to the controls Khalifa evaluates; nothing here is certified',
  },
};

export function frameworkLabel(id: string): string {
  return FRAMEWORKS[id]?.label ?? id;
}
