# Slack setup

Slack is off by default. A Git deploy ships it disabled and kill-switched, and
nothing in the app's files needs editing to turn it on. Every value below is
entered once in the app and kept in its Lakebase database, so later Deploy from
Git updates keep it.

Never paste secret values into email or chat. Part C says where they go.

## Part A. Create the Slack app (Slack workspace admin)

1. Create a Slack app from `bundle/slack/production.manifest.json`, or from
   `development.manifest.json` for a test workspace.
2. Turn on **Socket Mode**. The app does not use Events API HTTP delivery.
3. Under **Basic Information > App-Level Tokens**, create a token with the
   `connections:write` scope. It has the `xapp…` format.
4. Install the app to the workspace. The bot token appears under **OAuth &
   Permissions** and has the `xoxb…` format.
5. Under **App Home**, turn the Messages tab on and check "Allow users to send
   Slash commands and messages from the messages tab". Without this, Slack
   shows "Sending messages to this app has been turned off."
6. Note the Slack **Team ID** of the workspace.

## Part B. Create one Databricks OAuth app (account admin)

This lets each Slack user sign in once and keep their own data access.

1. In the Databricks account console, open Settings > App connections > Add
   connection.
2. Redirect URL: `<APP URL>/api/slack/oauth/callback`.
3. Scopes: `all-apis`, `offline_access`, `openid`, `profile`, `email`.
4. Client type: confidential. Generate a client secret.
5. Save. Copy the client secret straight into Part C; it is shown only once.
   Keep the **client ID** for Part E.

## Part C. Store four secrets in one secret scope

Use these key names unless you change them in the app.

| Key | Value |
|---|---|
| `insight-agent-slack-app-token` | The `xapp…` token from Part A. |
| `insight-agent-slack-bot-oauth-token` | The `xoxb…` token from Part A. |
| `insight-agent-slack-oauth-client-secret` | The client secret from Part B. |
| `insight-agent-slack-broker-key` | A new random key from `openssl rand -base64 32`. |

```bash
databricks secrets create-scope <SCOPE>
databricks secrets put-secret <SCOPE> insight-agent-slack-app-token
databricks secrets put-secret <SCOPE> insight-agent-slack-bot-oauth-token
databricks secrets put-secret <SCOPE> insight-agent-slack-oauth-client-secret
databricks secrets put-secret <SCOPE> insight-agent-slack-broker-key
```

Each command prompts for the value.

## Part D. Let the app read that scope

Copy the app's **service principal** ID from its page under Compute > Apps,
then run:

```bash
databricks secrets put-acl <SCOPE> <APP SERVICE PRINCIPAL ID> READ
```

This is the only link between the app and the secrets. You do not need to add
app resources or edit app files.

## Part E. Enter the Slack values in the app

Sign in as an admin and open Settings > Environment > Slack connection.

| Field | Value |
|---|---|
| Slack Team ID | From Part A. |
| Databricks workspace address | `https://<workspace host>` |
| App address | `<APP URL>` |
| Databricks OAuth client ID | From Part B. |
| Secret scope | `<SCOPE>` |

Select **Save Slack connection**, restart the app from its Databricks page,
then return to the same screen and select **Turn Slack on**.

## Part F. Before users try it

- Each user needs a Databricks identity with access to the Genie spaces and
  data they should see.
- On first use, each user messages the bot and follows the one-time sign-in
  link it sends. Answers then run as that user, under their own Unity Catalog
  permissions.

Operators running a reviewed bundle rollout instead of the in-app settings
should follow `bundle/slack/ROLLOUT.md`.
