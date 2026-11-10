# Elasticsearch Configuration

This directory contains Elasticsearch-related configuration files used during SIEM development.

## Final Deployment Configuration

The final Docker Compose deployment configures Elasticsearch through environment variables.

- Single-node discovery enabled
- Elasticsearch security disabled
- JVM heap allocation: 512 MB
- Persistent Elasticsearch data volume

## Security Configuration

An earlier development configuration used certificate-based SSL and Elasticsearch security.

That configuration is not included as an active configuration for the final Docker Compose deployment.

## Important

- Certificate files and private keys must not be committed.
- The final deployment settings are maintained in the root `docker-compose.yml`.
- `instances.yml` is retained as a development configuration artifact.
