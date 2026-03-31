# Security Graph - Operational Checklist

## A. EKS Architecture Summary

### Components
1. **api-service** - REST API deployment (2 replicas, HPA to 10)
2. **rule-runner** - CronJob running every 6 hours
3. **IRSA roles** - IAM roles for pod authentication to Neptune/DynamoDB

### Network Flow
```
User → ALB (443) → api-service (ClusterIP) → Neptune (8182)
                                                    ↓
                                            DynamoDB (Issues table)
```

## B. IRSA Configuration (Critical for Security)

### API Service Role Permissions
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "dynamodb:GetItem",
      "dynamodb:Query", 
      "dynamodb:Scan",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem"
    ],
    "Resource": [
      "arn:aws:dynamodb:REGION:ACCOUNT:table/SecurityIssues",
      "arn:aws:dynamodb:REGION:ACCOUNT:table/SecurityIssues/index/*"
    ]
  }, {
    "Effect": "Allow",
    "Action": ["neptune-db:Connect"],
    "Resource": "arn:aws:neptune-db:REGION:ACCOUNT:*"
  }]
}
```

### Rule Runner Role Permissions
Same as API Service + `dynamodb:UpdateItem` for status updates.

## C. Network Policies

### Pod Egress Restrictions
- **api-service**: Only to Neptune (8182), AWS API (443)
- **rule-runner**: Only to Neptune (8182), AWS API (443), DynamoDB

Apply with:
```bash
kubectl apply -f eks-manifests/08-network-policy.yaml
```

## D. Logging & Observability

### CloudWatch Setup
```bash
# Log group retention
aws logs put-retention-policy \
  --log-group-name /aws/eks/security-graph-cluster/workload \
  --retention-in-days 90
```

### Recommended Dashboards
1. API latency (p50, p95, p99)
2. Issue count by severity
3. Rule execution success/failure
4. Neptune query latency

## E. SLOs

| Service | SLO | Alert Threshold |
|---------|-----|-----------------|
| API | 99.9% availability | < 99.5% for 5 min |
| API | p99 latency < 500ms | > 1s for 5 min |
| Rule Runner | 99% execution success | > 2 failures/day |
| Rule Runner | Execution < 30 min | > 45 min |

## F. Runbooks

### Runbook: API Pod High CPU
1. Check HPA: `kubectl get hpa -n security-graph`
2. Describe pod: `kubectl describe pod -l app=api-service -n security-graph`
3. Check logs: `kubectl logs -l app=api-service -n security-graph --tail=100`
4. Scale manually if needed: `kubectl scale deployment api-service --replicas=5 -n security-graph`

### Runbook: Rule Runner Job Failed
1. Check job status: `kubectl get job -n security-graph`
2. View logs: `kubectl logs job/<job-name> -n security-graph`
3. Check Neptune connectivity from pod
4. Retry manually: `kubectl create job --from=cronjob/rule-runner rule-runner-manual -n security-graph`

### Runbook: Neptune Query Timeout
1. Check Neptune cluster status in Console
2. Increase query timeout in configmap
3. Check for long-running queries in Neptune Insights
4. Consider scaling Neptune instance

## G. Security Hardening

### Must Do Before Production
1. [ ] Enable VPC Flow Logs
2. [ ] Configure GuardDuty on all accounts
3. [ ] Enable CloudTrail with Lake integration
4. [ ] Restrict IAM roles to minimum required permissions
5. [ ] Enable encryption at rest for DynamoDB
6. [ ] Enable encryption in transit for Neptune
7. [ ] Configure WAF on ALB
8. [ ] Review and restrict NetworkPolicies
9. [ ] Enable Pod Security Standards (restricted)
10. [ ] Configure RBAC for namespace access

## H. Deployment Commands

```bash
# Deploy manifests
kubectl apply -f eks-manifests/

# Check deployment status
kubectl rollout status deployment/api-service -n security-graph

# View API logs
kubectl logs -l app=api-service -n security-graph -f

# Scale API service
kubectl scale deployment api-service --replicas=5 -n security-graph

# Manual rule runner execution
kubectl create job --from=cronjob/rule-runner rule-runner-manual -n security-graph
```

## I. Monitoring URLs

- CloudWatch Log Insights: `/aws/eks/security-graph-cluster/workload`
- X-Ray: Service map for api-service
- Prometheus metrics: `http://<pod>:8080/metrics`
