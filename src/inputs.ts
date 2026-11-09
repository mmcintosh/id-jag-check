// The step's inputs, from the INPUT_* variables the runner sets (the input's name upper-cased, spaces as "_").
import { CLIENT_AUTH_METHODS, type ClientAuthMethod, SUBJECT_TOKEN_TYPES, type SubjectTokenType } from "./exchange.js";
import { FAIL_ON, type FailOn, InputError, type RunInput } from "./run.js";

type Env = Record<string, string | undefined>;

export const input = (env: Env, name: string): string => (env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] ?? "").trim();

/** The inputs that are secrets: the caller masks each one before anything is printed. */
export const SECRET_INPUTS = ["id-jag", "subject-token", "idp-client-secret"] as const;

const MINT_INPUTS = ["subject-token", "idp-client-id", "idp-client-secret"] as const;

export function readInputs(env: Env, now: number): RunInput {
  const required = (name: string) => {
    const v = input(env, name);
    if (!v) throw new InputError(`The input ${name} is required.`);
    return v;
  };
  const scopes = required("scopes").split(/\s+/).filter(Boolean);
  const failOn = input(env, "fail-on") || "must";
  if (!(FAIL_ON as readonly string[]).includes(failOn)) throw new InputError(`fail-on must be one of ${FAIL_ON.join(", ")}; it is ${JSON.stringify(failOn)}.`);

  const idJag = input(env, "id-jag");
  const minting = [...MINT_INPUTS, "token-endpoint"].filter((n) => input(env, n));
  let source: RunInput["idJag"];
  if (idJag) {
    if (minting.length > 0) throw new InputError(`Give either id-jag or the inputs to mint one (${MINT_INPUTS.join(", ")}, token-endpoint), not both.`);
    source = { token: idJag };
  } else {
    if (minting.length === 0) throw new InputError(`Give id-jag, or ${MINT_INPUTS.join(", ")} to mint one.`);
    for (const n of MINT_INPUTS) required(n);
    const subjectTokenType = input(env, "subject-token-type") || "id_token";
    if (!Object.hasOwn(SUBJECT_TOKEN_TYPES, subjectTokenType)) throw new InputError(`subject-token-type must be one of ${Object.keys(SUBJECT_TOKEN_TYPES).join(", ")}; it is ${JSON.stringify(subjectTokenType)}.`);
    const clientAuth = input(env, "idp-client-auth") || "client_secret_basic";
    if (!(CLIENT_AUTH_METHODS as readonly string[]).includes(clientAuth)) throw new InputError(`idp-client-auth must be one of ${CLIENT_AUTH_METHODS.join(", ")}; it is ${JSON.stringify(clientAuth)}.`);
    source = {
      mint: {
        tokenEndpoint: input(env, "token-endpoint") || undefined,
        clientId: required("idp-client-id"),
        clientSecret: required("idp-client-secret"),
        clientAuth: clientAuth as ClientAuthMethod,
        subjectToken: required("subject-token"),
        subjectTokenType: subjectTokenType as SubjectTokenType,
        audience: required("audience"),
        resource: required("resource"),
        scopes,
      },
    };
  }

  return {
    issuer: required("issuer"),
    audience: required("audience"),
    resource: required("resource"),
    scopes,
    clientId: input(env, "client-id") || undefined,
    idJag: source,
    failOn: failOn as FailOn,
    now,
  };
}
