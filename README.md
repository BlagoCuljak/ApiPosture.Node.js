# ApiPosture CLI for Node.js

Static source-code analysis CLI for Node.js API frameworks to identify authorization misconfigurations and security risks.

## Features

- **Multi-Framework Support**: Express.js, NestJS, Fastify, and Koa
- **8 Security Rules**: Covering exposure, consistency, privilege, and surface area risks
- **Multiple Output Formats**: Terminal, JSON, and Markdown
- **Configurable**: Rule customization and suppression support
- **CI/CD Ready**: Exit codes for pipeline integration

## Installation

```bash
npm install -g @apiposture/cli
```

Or use with npx:

```bash
npx @apiposture/cli scan .
```

## Quick Start

```bash
# Scan current directory
apiposture scan

# Scan specific path
apiposture scan ./src

# Output as JSON
apiposture scan -o json

# Fail CI if critical findings
apiposture scan --fail-on critical
```

## Security Rules

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| AP001 | Public without explicit intent | High | Endpoint is public without @Public or allowAnonymous marker |
| AP002 | AllowAnonymous on write | High | Write operation explicitly marked as public |
| AP003 | Controller/action conflict | Medium | Method @Public overrides class-level guards (NestJS) |
| AP004 | Missing auth on writes | Critical | Unprotected write endpoint |
| AP005 | Excessive role access | Low | Endpoint allows >3 roles |
| AP006 | Weak role naming | Low | Generic role names like "admin", "user" |
| AP007 | Sensitive route keywords | Medium | Public route contains admin/debug/internal |
| AP008 | Unprotected endpoint | High | No middleware chain at all |

## CLI Options

```bash
apiposture scan [path]

Options:
  -o, --output <format>        Output format: terminal, json, markdown (default: terminal)
  -f, --output-file <path>     Write output to file
  -c, --config <path>          Config file path (.apiposture.json)
  --severity <level>           Min severity: info, low, medium, high, critical
  --fail-on <level>            Exit code 1 if findings at this level
  --sort-by <field>            Sort by: severity, route, method, classification
  --sort-dir <dir>             Sort direction: asc, desc
  --classification <types>     Filter: public, authenticated, role-restricted, policy-restricted
  --method <methods>           Filter: GET, POST, PUT, DELETE, PATCH
  --route-contains <str>       Filter routes containing string
  --api-style <styles>         Filter: express, nestjs, fastify, koa
  --rule <rules>               Filter by rule ID (comma-separated)
  --no-color                   Disable colors
  --no-icons                   Disable icons

License Commands:
  apiposture license activate <key>    Activate a license
  apiposture license deactivate        Deactivate current license
  apiposture license status            Show license status
```

## Configuration

Create `.apiposture.json` in your project root:

```json
{
  "rules": {
    "AP001": { "enabled": true },
    "AP005": { "enabled": true, "options": { "maxRoles": 3 } }
  },
  "suppressions": [
    {
      "ruleId": "AP001",
      "route": "/api/health",
      "reason": "Health check is intentionally public"
    }
  ],
  "scan": {
    "excludePatterns": ["**/test/**"]
  }
}
```

## Supported Frameworks

### Express.js
```javascript
app.get('/path', handler);
router.post('/path', authMiddleware, handler);
app.use('/prefix', router);
```

### NestJS
```typescript
@Controller('path')
@UseGuards(AuthGuard)
class MyController {
  @Get()
  @Roles('admin')
  handler() {}
}
```

### Fastify
```javascript
fastify.get('/path', { preHandler: [auth] }, handler);
fastify.route({ method: 'GET', url: '/path', handler });
```

### Koa
```javascript
router.get('/path', authMiddleware, handler);
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: npx @apiposture/cli scan --fail-on high -o json -f report.json
```

```yaml
# GitLab CI
security-scan:
  script:
    - npx @apiposture/cli scan --fail-on critical
```

## Environment Variables

- `APIPOSTURE_LICENSE_KEY`: License key for Pro features

## License

MIT
