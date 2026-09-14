# Insight Agent Harness API Access Reference

**Classification:** Public / reference

Insight Agent Harness currently publishes no stable deployed runtime API. The
repository contains contracts and validation helpers; it does not claim a
hosted Databricks App or Model Serving endpoint. Do not infer an HTTP route from
a schema or package name.

## Databricks access patterns

Databricks supports several distinct access surfaces:

- An Apps-hosted `ResponsesAgent` or `AgentServer` may expose `POST /responses`.
- A custom Databricks App may define its own `/api/*` routes.
- A Model Serving endpoint may be invoked through its endpoint API.
- SQL `ai_query()` targets supported Model Serving endpoints, not arbitrary
  custom App routes.

OpenAI compatibility describes a request and response protocol. It does not
make every custom App route OpenAI-compatible and does not imply that this
harness implements `/responses`.

## Authentication boundary

Use Databricks OAuth for Databricks Apps. Personal access tokens (PATs) are not
supported for Apps-hosted agent access. The caller still needs the platform
permission required by the selected surface, such as **CAN USE** on an App or
**CAN QUERY** on a Model Serving endpoint.

Never hardcode, commit, print, or log OAuth tokens, client secrets, cookies, or
raw authorization headers. Validate identity and authorization server-side and
preserve Unity Catalog grants, row filters, and column masks.

## Publication boundary

A downstream product must document and version its own routes, request and
response schemas, identity context, streaming behavior, and error contract.
Nothing in this neutral mirror authorizes direct invocation of a private
application or model.

## Official sources

- [Query an agent deployed on Databricks](https://docs.databricks.com/aws/en/agents/custom-agents/query-agent)
- [Connect to a Databricks App API using token authentication](https://docs.databricks.com/aws/en/dev-tools/databricks-apps/connect-local)
- [`ai_query` function](https://docs.databricks.com/aws/en/sql/language-manual/functions/ai_query)
