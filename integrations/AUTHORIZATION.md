# Shared authorization service

AtomicServer can run the same open-source authorization code in two modes:

- Direct: the user's server owns a provider OAuth app (existing Notion setup).
- Managed: a separately deployed AtomicServer owns the app and handles its
  callback; the user's server retrieves the result over outbound HTTP.

Notion is the first provider. Sync execution, resource discovery, mappings,
checkpoint storage and automation APIs are identical in both modes. This service
is not a proxy for provider data. Atomic SaaS deployment and automated server
provisioning are separate operational work; the transport currently uses
administrator-provisioned per-server credentials.

## Service configuration

Set these on the authorization-service deployment, then restart it:

```
ATOMIC_OAUTH_PUBLIC_URL=https://auth.example.com
ATOMIC_OAUTH_CLIENTS={"server-a":"<unique random server credential of at least 32 characters>"}
ATOMIC_NOTION_CLIENT_ID=<provider application ID>
ATOMIC_NOTION_CLIENT_SECRET=<provider application secret>
```

Register `https://auth.example.com/oauth-service/notion/callback` as the exact
redirect URI with Notion. The service needs no frontend-origin configuration.
The public URL must be an origin, without a path, query or credentials. HTTP is
accepted only for localhost/127.0.0.1 development. Store environment secrets in
the deployment's secret manager, never in frontend variables or version control.
Each server must get its own unique, randomly generated credential. Operators
restart the service after changing the client allowlist. Automated enrollment,
credential rotation without restart and account/billing integration remain open.

Without `ATOMIC_OAUTH_PUBLIC_URL`, service routes are not registered. Startup
fails for incomplete service configuration. The node's encrypted secret store
holds pending provider credentials. Cleanup scans bounded pages every 30 seconds;
expired credentials are reclaimed as those pages are processed, rather than at
an exact per-record deletion deadline.

## User AtomicServer configuration

```
ATOMIC_OAUTH_SERVICE_URL=https://auth.example.com
ATOMIC_OAUTH_SERVICE_TOKEN=<the credential provisioned for this server>
```

Restart the user's server. It does not need the Notion app secret, a public
callback URL or inbound reachability. This mode takes precedence over direct
Notion OAuth configuration. Remove these two settings to return to direct mode.
Existing provider credentials and plugin bindings are preserved.

## Protocol

1. The browser makes a signed start request to its own AtomicServer. That server
   verifies drive access and any existing connection's ownership.
2. The host calls `POST /oauth-service/notion/start` with its service credential
   in the Authorization header and an actor/drive/attempt binding. The service
   derives server identity from that credential; a body-supplied server ID is
   rejected. Admission is capped at ten starts per minute per server.
3. The service returns the Notion authorization URL, a public attempt ID and a
   private retrieval proof. The host wraps the ticket in its secret store and
   sends only the URL, its local state and `mode: managed` to the browser.
4. Notion calls the service's callback. The service claims the random state
   once, exchanges the code using the shared provider adapter, and wraps the
   result. Duplicate callbacks cannot repeat the exchange.
5. The browser polls its own signed finish endpoint. The host calls
   `POST /oauth-service/notion/redeem` with its service credential, ticket proof
   and original binding. The service checks all dimensions of that binding.
6. Pending attempts return a pending marker. Ready credentials are consumed
   before delivery, then removed from the service's secret store. The user's
   host stores them in the existing reusable connection and returns only public
   connection details to the browser.

There is no callback from the service to an arbitrary host URL, avoiding both
inbound localhost requirements and callback SSRF. Clients refuse redirects and
non-loopback plaintext transport. Credential responses are bounded and marked
`Cache-Control: no-store`. Provider callback URLs necessarily contain a temporary
OAuth code; deployments must redact query strings on these callback routes in
reverse-proxy/access logs. Tokens and retrieval proofs must never be logged.

A lost redemption response requires fresh authorization: the service will not
send the credentials twice. Reconnecting to another Notion workspace is refused.
Service outages are surfaced as errors without enabling sync or approving writes.
Cancelled browser attempts expire on the service; immediate remote cancellation
is not implemented. Automatic provider refresh and a shared-connection revocation
UI also remain open. Disabling a host's service credential prevents new retrieval,
but does not revoke provider credentials already delivered to that host.

## Evidence

OAuth tests exercise the actual HTTP service/client over a loopback listener,
plus authentication, forged server IDs, another server's redemption, callback
cancellation/replay, admission and expiry. Browser fixtures exercise both direct
and managed sign-in through named database selection and native mapping creation.
They do not contact Notion. Real provider registration, consent, token refresh
and a disposable-database two-way test remain separate acceptance work.
