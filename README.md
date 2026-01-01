# Zimara Test Fixtures

Intentionally insecure scripts and files used to validate Zimara security checks.

⚠️ **WARNING**
This repository contains:
- Hardcoded secrets
- Insecure configurations
- Deliberate violations of security best practices

**DO NOT use these files in production environments.**

## Purpose

This repository exists to:
- Validate Zimara detection logic
- Regression-test new checks
- Compare results across Zimara versions

## Usage

```bash
./zimara-violation-fixtures.sh
zimara scan ./zimara-violation-fixtures
