# id-jag-check

A GitHub Action that checks the ID-JAGs (Identity Assertion JWT Authorization Grants) your IdP issues, rule by rule,
against [draft-ietf-oauth-identity-assertion-authz-grant-06](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/06/).
ID-JAGs are what Cross App Access and MCP's enterprise-managed authorization run on. Add it to your IdP's CI, and a
change that would make receivers refuse your ID-JAGs fails the build, with every rule's result in the job summary.
Not released yet.

The rules are [better-auth-id-jag](https://www.npmjs.com/package/better-auth-id-jag)'s `checkIssuerMetadata` and
`checkIdJag` ([source](https://github.com/mmcintosh/better-auth-id-jag/blob/main/src/core/check.ts)), the same ones
the public tester at https://idjag-tester.infowall.net reports. Each comes with its level (the draft's MUST, SHOULD,
RECOMMENDED or OPTIONAL, or POLICY for that receiver's own choice) and its source, a section of the draft or an RFC.

## Use it

Check an ID-JAG an earlier step got from your IdP:

```yaml
- uses: mmcintosh/id-jag-check@v1
  with:
    issuer: https://idp.staging.example.com
    audience: https://mcp.example.com/api/auth   # the receiver's issuer identifier: the ID-JAG's aud
    resource: https://mcp.example.com/mcp        # the protected resource the receiver governs
    scopes: read write                           # the scopes the receiver grants
    client-id: the-client-id-at-the-receiver
    id-jag: ${{ steps.exchange.outputs.id-jag }}
```

Or let the Action ask your IdP for one, with the token exchange of draft -06 section 4.3:

```yaml
- uses: mmcintosh/id-jag-check@v1
  with:
    issuer: https://idp.staging.example.com
    audience: https://mcp.example.com/api/auth
    resource: https://mcp.example.com/mcp
    scopes: read write
    client-id: the-client-id-at-the-receiver
    idp-client-id: ${{ vars.IDP_CLIENT_ID }}
    idp-client-secret: ${{ secrets.IDP_CLIENT_SECRET }}
    subject-token: ${{ steps.sign-in.outputs.id-token }}   # an ID token for a test user, from your IdP
```

### Inputs

| Input | Required | What it is |
|---|---|---|
| `issuer` | yes | Your IdP's issuer identifier (https). Its metadata and JWKS are fetched from it. |
| `audience` | yes | The receiver's issuer identifier, which the ID-JAG's `aud` must be. |
| `resource` | yes | The protected resource the receiver governs. |
| `scopes` | yes | The scopes the receiver grants, space-separated. The ID-JAG must carry at least one. |
| `client-id` | no | The client's id at the receiver, which the ID-JAG's `client_id` must be. Without it, `client_id` is only checked for presence. |
| `id-jag` | one of the two | The ID-JAG to check. Masked in the log. |
| `idp-client-id`, `idp-client-secret`, `subject-token` | one of the two | To mint the ID-JAG instead: the client's id and secret at your IdP, and the subject token. The secret and the subject token are masked in the log. |
| `token-endpoint` | no | Your IdP's token endpoint, for minting. Defaults to `token_endpoint` from your metadata. |
| `idp-client-auth` | no | `client_secret_basic` (the default) or `client_secret_post`. |
| `subject-token-type` | no | `id_token` (the default), `refresh_token` or `saml2`. |
| `fail-on` | no | `fail` (the default) stops the step when a rule fails; `warn` also stops it on a warning. |

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
   and every claim (`jwt.*`, `header.*`, `signature`, `claim.*`, `receiver.parse`).

The rules this Action adds, for the steps only it does:

| Rule | Level | Source | Checks |
|---|---|---|---|
| `metadata.fetch` | SHOULD | draft -06 section 7.1; RFC 8414 section 3 | Metadata is found at one of the two locations. |
| `jwks.fetch` | MUST | draft -06 section 7.1 | The metadata's `jwks_uri` answers with JSON. |
| `exchange.response` | MUST | draft -06 section 4.3.4; RFC 8693 section 2.2 | The exchange answers HTTP 200 with a JSON object. |
| `exchange.issued_token_type` | MUST | draft -06 section 4.3.4 | `urn:ietf:params:oauth:token-type:id-jag`. |
| `exchange.token_type` | MUST | draft -06 section 4.3.4; RFC 6749 section 5.1 | `N_A`. |
| `exchange.cache_control` | MUST | RFC 6749 section 5.1; RFC 8693 section 2.2.1 | `Cache-Control: no-store`. |
| `exchange.access_token` | MUST | draft -06 section 4.3.4 | Present: it carries the ID-JAG. |
| `exchange.expires_in` | RECOMMENDED | draft -06 section 4.3.4 | A positive whole number of seconds. |
| `exchange.refresh_token` | SHOULD | draft -06 section 4.3.4 | Absent ("SHOULD NOT be used"). |
| `exchange.scope` | MUST, or OPTIONAL | draft -06 section 4.3.4 | Present whenever the ID-JAG's scope differs from the scopes asked for. |

## What it doesn't check

- **How your IdP decides** (draft -06 section 4.3.3: who may get an ID-JAG, for which audience and scopes). The
  Action sees only what your IdP answers.
- **Whether a receiver accepts it.** The Action doesn't redeem the ID-JAG anywhere. The public tester does, with a
  real receiver.
- **Every MUST in the draft.** It isn't a conformance or certification test.

## What it sends, and what it shows

- **Requests:** only to your issuer's two metadata locations, its `jwks_uri` and, when minting, its token endpoint.
  Each is https only, follows no redirects, reads at most 256 KiB and gives up after 10 seconds
  (`src/http.ts`). Nothing is sent anywhere else, and there is no telemetry.
- **Secrets:** `id-jag`, `idp-client-secret`, `subject-token` and a minted ID-JAG are masked before anything is
  printed.
- **The report** shows the ID-JAG's header and its claims' names. Of their values, it shows only those that name the
  setup (`iss`, `aud`, `client_id`, `resource`, `scope`, `jti`, `iat`, `exp`, `nbf`, `tenant`), never `sub`, `email`
  or other values about the user (`src/report.ts`). From a refused exchange it shows the `error` code, not the
  `error_description`, which can name the user.

The tests (`test/action.test.ts`) hold each of these: a redirect not followed, the size cap, the masks, and the
user's values absent from the log, the summary and the outputs.

## Contributing

Commits, pull requests and their descriptions credit people only: no AI co-authors, no "generated with" lines, no
commits made by AI accounts. A check (`.github/workflows/commit-text.yml`) enforces it on every pull request and on
`main`; to catch it before you commit, run `git config core.hooksPath .githooks` once in your clone.

To work on it: `npm ci`, then `npm run typecheck`, `npm test` and `npm run build`. The runner runs `dist/index.js`,
so commit it with the source; CI fails when it doesn't match. `dist/licenses.txt` carries the licences of the
packages bundled into it.

## License

MIT
