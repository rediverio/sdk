# GitLab CI Examples

Examples for integrating Rediver Agent into GitLab CI/CD pipelines.

## Quick Start

Copy `minimal.gitlab-ci.yml` to `.gitlab-ci.yml` in your repository:

```bash
cp minimal.gitlab-ci.yml /path/to/your/repo/.gitlab-ci.yml
```

## Available Examples

| File | Description | Use Case |
|------|-------------|----------|
| `minimal.gitlab-ci.yml` | Simplest setup | Quick start, basic scanning |
| `.gitlab-ci.yml` | Full-featured pipeline | Production use with all features |

## Features

### Auto CI Detection
The agent automatically detects GitLab CI environment and:
- Extracts MR/commit information from environment variables
- Determines scan strategy (all files vs changed files only)
- Posts inline comments on MR diffs

### Inline MR Comments
When running in a MR context, findings are posted as inline comments on changed lines:

```yaml
mr-security-review:
  image: ghcr.io/rediverio/rediver-agent:ci
  variables:
    GITLAB_TOKEN: $CI_JOB_TOKEN
  script:
    - rediver-agent -tools semgrep -target . -auto-ci -comments -verbose
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

### GitLab Security Dashboard Integration
Generate SARIF reports for GitLab's Security Dashboard:

```yaml
artifacts:
  reports:
    sast: gl-sast-report.json
    dependency_scanning: dependencies.json
    container_scanning: container-results.json
```

### Push to Rediver Platform
Send results to Rediver platform for tracking:

```yaml
variables:
  REDIVER_API_URL: $REDIVER_API_URL
  REDIVER_API_KEY: $REDIVER_API_KEY
script:
  - rediver-agent -tools semgrep,gitleaks,trivy -target . -push
```

## Environment Variables

### Auto-detected by Agent

| Variable | Description |
|----------|-------------|
| `GITLAB_CI` | Indicates GitLab CI environment |
| `CI_PROJECT_ID` | Project ID |
| `CI_PROJECT_URL` | Project URL |
| `CI_COMMIT_SHA` | Current commit SHA |
| `CI_COMMIT_BRANCH` | Current branch |
| `CI_MERGE_REQUEST_IID` | MR number |
| `CI_MERGE_REQUEST_DIFF_BASE_SHA` | Base commit for diff |

### Required Secrets (CI/CD Variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `CI_JOB_TOKEN` | Auto | Provided by GitLab, used for MR comments |
| `REDIVER_API_URL` | Optional | Rediver platform API URL |
| `REDIVER_API_KEY` | Optional | Rediver platform API key |

## Job Templates

### SAST Scanning

```yaml
sast:
  stage: security
  image: ghcr.io/rediverio/rediver-agent:ci
  script:
    - rediver-agent -tool semgrep -target . -verbose -sarif -sarif-output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Secret Detection

```yaml
secret-detection:
  stage: security
  image: ghcr.io/rediverio/rediver-agent:ci
  script:
    - |
      rediver-agent -tool gitleaks -target . -verbose -json -output secrets.json
      SECRETS=$(cat secrets.json | jq '.findings | length')
      if [ "$SECRETS" -gt 0 ]; then
        exit 1
      fi
```

### Dependency Scanning

```yaml
dependency-scan:
  stage: security
  image: ghcr.io/rediverio/rediver-agent:ci
  script:
    - rediver-agent -tool trivy -target . -verbose -json -output dependencies.json
  artifacts:
    reports:
      dependency_scanning: dependencies.json
```

### Container Scanning

```yaml
container-scan:
  stage: security
  image: ghcr.io/rediverio/rediver-agent:ci
  services:
    - docker:dind
  variables:
    DOCKER_HOST: tcp://docker:2375
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - rediver-agent -tool trivy-image -target $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA -verbose
```

### IaC Scanning

```yaml
iac-scan:
  stage: security
  image: ghcr.io/rediverio/rediver-agent:ci
  script:
    - rediver-agent -tool trivy-config -target . -verbose
  rules:
    - changes:
        - "**/*.tf"
        - "**/Dockerfile*"
```

## Scheduled Pipelines

For weekly security audits, create a scheduled pipeline:

1. Go to **CI/CD → Schedules**
2. Create new schedule with cron: `0 0 * * 0` (weekly)
3. Add the `weekly-audit` job from the full example

## Fail on Critical Findings

```yaml
script:
  - |
    rediver-agent -tools semgrep -target . -json -output results.json
    CRITICAL=$(cat results.json | jq '[.findings[] | select(.severity == "critical")] | length')
    if [ "$CRITICAL" -gt 0 ]; then
      echo "Found $CRITICAL critical findings!"
      exit 1
    fi
```
