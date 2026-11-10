# id-jag-check

A GitHub Action that checks the ID-JAGs (Identity Assertion JWT Authorization Grants) your IdP issues, rule by rule,
against [draft-ietf-oauth-identity-assertion-authz-grant-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/).
ID-JAGs are what Cross App Access and MCP's enterprise-managed authorization run on. Add it to your IdP's CI, and a
change that breaks one of the draft's MUSTs fails the build (with `fail-on: policy`, so does one that
better-auth-id-jag's receiver would refuse), with every rule's result in the job summary.

The rules are [better-auth-id-jag](https://www.npmjs.com/package/better-auth-id-jag)'s `checkIssuerMetadata` and
`checkIdJag` ([source](https://github.com/mmcintosh/better-auth-id-jag/blob/main/src/core/check.ts)), the same ones
the public tester at https://idjag-tester.infowall.net reports. Each comes with its level (the draft's MUST, SHOULD,
RECOMMENDED or OPTIONAL, or POLICY for that receiver's own choice) and its source, a section of the draft or an RFC.

## Use it

Let the Action ask your IdP for an ID-JAG, with the token exchange of draft -06 section 4.3, here for a test user
whose refresh token is kept as a secret:

```yaml
name: ID-JAG check
on:
  push: { branches: [main] }
  schedule: [{ cron: "0 6 * * *" }]
permissions: { contents: read }
jobs:
  id-jag:
    runs-on: ubuntu-24.04
    steps:
      - uses: mmcintosh/id-jag-check@v1
        with:
          issuer: https://idp.staging.example.com
          audience: https://mcp.example.com/api/auth   # the receiver's issuer identifier: the ID-JAG's aud
          resource: https://mcp.example.com/mcp        # the protected resource the receiver governs
          scopes: read write                           # the scopes the receiver grants
          client-id: the-client-id-at-the-receiver
          idp-client-id: ${{ vars.IDP_CLIENT_ID }}
          idp-client-secret: ${{ secrets.IDP_CLIENT_SECRET }}
          subject-token: ${{ secrets.TEST_USER_REFRESH_TOKEN }}
          subject-token-type: refresh_token
```

Or check an ID-JAG an earlier step got from your IdP. That step must mask it before it sets its output: the runner
prints a step's inputs before the Action starts, and only values it already masks (secrets, and anything masked with
`::add-mask::`) are hidden there.

```yaml
- id: exchange
  run: |
    token=$(./get-id-jag.sh)               # however your tests get one
    echo "::add-mask::$token"
    echo "id-jag=$token" >> "$GITHUB_OUTPUT"
- uses: mmcintosh/id-jag-check@v1
  with:
    issuer: https://idp.staging.example.com
    audience: https://mcp.example.com/api/auth
    resource: https://mcp.example.com/mcp
    scopes: read write
    client-id: the-client-id-at-the-receiver
    id-jag: ${{ steps.exchange.outputs.id-jag }}
```

The same goes for a `subject-token` from a step output.

### Inputs

| Input | Required | What it is |
|---|---|---|
| `issuer` | yes | Your IdP's issuer identifier (https). Its metadata and JWKS are fetched from it. |
| `audience` | yes | The receiver's issuer identifier, which the ID-JAG's `aud` must be. |
| `resource` | yes | The protected resource the receiver governs. |
| `scopes` | yes | The scopes the receiver grants, space-separated. The ID-JAG must carry at least one. |
| `client-id` | no | The client's id at the receiver, which the ID-JAG's `client_id` must be. Without it, `client_id` is only checked for presence. |
| `id-jag` | one of the two | The ID-JAG to check. Mask it in the step that produces it (above). |
| `idp-client-id`, `idp-client-secret`, `subject-token` | one of the two | To mint the ID-JAG instead: the client's id and secret at your IdP, and the subject token. Pass the secret and the subject token from secrets, or mask them first. |
| `token-endpoint` | no | Your IdP's token endpoint, for minting. Defaults to `token_endpoint` from your metadata, but only when the metadata's `issuer` is yours. |
| `idp-client-auth` | no | `client_secret_basic` (the default) or `client_secret_post`. Other methods, such as `private_key_jwt`, aren't supported. |
| `subject-token-type` | no | `id_token` (the default), `refresh_token` or `saml2`. |
| `fail-on` | no | What stops the step: `must` (the default), `policy` or `warn`. See below. |

### Outputs

| Output | What it is |
|---|---|
| `passed` | `true` when no rule stopped the step, else `false`. |
| `failed` | The ids of the rules that stopped the step, as a JSON array. |
| `report` | The report in Markdown, as written to the job summary. |

## What it checks

1. **Your metadata and keys,** found from `issuer` at RFC 8414's location, or OpenID Connect Discovery's as the
   fallback draft -06 section 7.1 allows: `checkIssuerMetadata`'s rules (`metadata.*`, `jwks.*`).
2. **When it mints the ID-JAG,** your token endpoint's answer (draft -06 section 4.3.4): the rules below.
3. **The ID-JAG:** `checkIdJag`'s rules, from its structure and header to its signature (with your published keys)
   and every claim (`jwt.*`, `header.*`, `signature`, `claim.*`, `receiver.parse`). A header or claims nested more
   than 32 levels deep fail `jwt.structure` (RFC 7519 section 7.2) and aren't checked further.

**What stops the step,** by `fail-on`:

- `must` (the default): a failed MUST of the draft or an RFC, or a failed rule that stops a receiver from registering
  your IdP (your metadata's `issuer`, an https `jwks_uri`, usable public keys).
- `policy`: also a failed POLICY rule, what better-auth-id-jag's receiver refuses though the draft allows it, such as
  `authorization_details`, a lifetime over 900 seconds or an algorithm it doesn't accept. `receiver.parse`, whether
  that receiver's parser accepts the ID-JAG, counts as POLICY here: each MUST it enforces has its own rule.
- `warn`: any failed rule at any level, and any warning.

Every rule's result is in the report whatever `fail-on` is.

The rules this Action adds, for the steps only it does:

| Rule | Level | Source | Checks |
|---|---|---|---|
| `metadata.fetch` | SHOULD | draft -06 section 7.1; RFC 8414 section 3 | Metadata is found at one of the two locations. |
| `jwks.fetch` | MUST | draft -06 section 4.4.1; RFC 7521 section 5.2 | The metadata's `jwks_uri` answers with JSON: a receiver verifies the signature with these keys. Not fetched when the metadata's `issuer` isn't yours (RFC 8414 section 3.3). |
| `metadata.check`, `jwt.check` | MUST | RFC 8414 section 3.2; draft -06 section 4.4.1 | The checks could read every value they needed. They aren't known to stop on any input; if one ever does, its rule fails and the rest of the report is kept. |
| `exchange.response` | MUST | draft -06 section 4.3.4; RFC 8693 section 2.2 | The exchange answers HTTP 200 with a JSON object. |
| `exchange.issued_token_type` | MUST | draft -06 section 4.3.4 | `urn:ietf:params:oauth:token-type:id-jag`. |
| `exchange.token_type` | MUST | draft -06 section 4.3.4; RFC 6749 section 5.1 | `N_A`. |
| `exchange.token_endpoint` | MUST | RFC 8414 sections 2, 3.3 | There is a token endpoint to mint with: `token-endpoint`, or `token_endpoint` from metadata whose `issuer` is yours. |
| `exchange.content_type` | MUST | RFC 6749 section 5.1; RFC 8693 section 2.2.1 | `Content-Type: application/json`. |
| `exchange.cache_control` | MUST | RFC 6749 section 5.1; RFC 8693 section 2.2 | `Cache-Control: no-store`. |
| `exchange.access_token` | MUST | draft -06 section 4.3.4 | Present: it carries the ID-JAG. |
| `exchange.expires_in` | RECOMMENDED | draft -06 section 4.3.4 | A positive whole number of seconds. |
| `exchange.refresh_token` | SHOULD | draft -06 section 4.3.4 | Absent ("SHOULD NOT be used"). |
| `exchange.scope` | MUST, or OPTIONAL | draft -06 section 4.3.4 | Present, and the same as the ID-JAG's scope, whenever that differs from the scopes asked for (MUST); otherwise OPTIONAL, and the same when present. |

## What it doesn't check

- **How your IdP decides** (draft -06 section 4.3.3: who may get an ID-JAG, for which audience and scopes). The
  Action sees only what your IdP answers.
- **Whether a receiver accepts it.** The Action doesn't redeem the ID-JAG anywhere. The public tester does, with a
  real receiver.
- **Every MUST in the draft.** It isn't a conformance or certification test. It doesn't check, for example, the
  `Pragma: no-cache` header RFC 6749 section 5.1 also asks of a token response.

## What it sends, and what it shows

- **Requests:** only to your issuer's two metadata locations, its `jwks_uri` and, when minting, its token endpoint.
  Each is https only, follows no redirects, reads at most 256 KiB, refuses JSON nested more than 32 levels deep and
  gives up after 10 seconds (`src/http.ts`). Nothing is sent anywhere else, and there is no telemetry.
- **Secrets:** the Action masks `id-jag`, `idp-client-secret`, `subject-token` and a minted ID-JAG before it prints
  anything. The runner prints the step's inputs before the Action starts, though, so pass them from secrets or mask
  them in the step that produces them (see [Use it](#use-it)).
- **The report** shows the ID-JAG's header and its claims' names. Of their values, it shows only those that name the
  setup (`iss`, `aud`, `client_id`, `resource`, `scope`, `jti`, `iat`, `exp`, `nbf`, `tenant`), never `sub`, `email`,
  an actor's `act.sub` or other values about the user, and takes them out of the rules' messages too (`src/run.ts`).
  Values from your IdP are escaped, so they can't become links, images or HTML in the summary (`src/report.ts`). From
  a refused exchange it shows the `error` code, not the `error_description`, which can name the user.

The tests (`test/action.test.ts`) hold each of these: a redirect not followed, the size cap and the timeout, metadata
naming another issuer left unused, the masks, the escaping, and the user's values absent from the log, the summary
and the outputs.

## Contributing

Commits, pull requests and their descriptions credit people only: no AI co-authors, no "generated with" lines, no
commits made by AI accounts. A check (`.github/workflows/commit-text.yml`) enforces it on every pull request and on
`main`; to catch it before you commit, run `git config core.hooksPath .githooks` once in your clone.

To work on it: `npm ci`, then `npm run typecheck`, `npm test` and `npm run build`. The runner runs `dist/index.js`,
so commit it with the source; CI fails when it doesn't match. `dist/licenses.txt` carries the licences of the
packages bundled into it.

## Related

- [better-auth-id-jag](https://github.com/mmcintosh/better-auth-id-jag): where this Action's rules come from. A pair
  of Better Auth plugins: an ID-JAG issuer for your IdP, and a receiver for your MCP server or other app.
- [Test your IdP](https://idjag-tester.infowall.net): the public tester, which also redeems your ID-JAG at a real
  receiver.

If id-jag-check is useful to you, a ⭐ on [GitHub](https://github.com/mmcintosh/id-jag-check) helps others find it.

## License

MIT © Mark McIntosh
