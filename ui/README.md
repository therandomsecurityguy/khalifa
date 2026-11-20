# Khalifa UI

Next.js application for the Khalifa security graph: issues and attack paths,
resource and secret exploration, compliance frameworks, CIEM views, and trends.

The browser never calls the API directly. Requests go to the same-origin proxy
at `app/api/[...path]`, which forwards to the API service and attaches the
verified identity — so the UI container needs no public API URL and no token.

## Run locally

```bash
npm ci                 # repo root — the workspace install
npm run dev -w ui      # http://localhost:3000
```

| Variable          | Default                 | Purpose                          |
| ----------------- | ----------------------- | -------------------------------- |
| `KHALIFA_API_URL` | `http://localhost:8080` | API origin the proxy forwards to |

## Test and build

```bash
npx jest --selectProjects ui        # component/unit tests
npm run build -w ui                 # production build (standalone output)
```

## Ship

Built by the root `Dockerfile` target `ui` and deployed by the Helm chart
(`ui.*` values in [`deploy/helm/khalifa`](../../deploy/helm/khalifa)) — digest-pinned
images only. The UI is exposed behind the API's ingress/Cloudflare Access in
the reference deployment.
