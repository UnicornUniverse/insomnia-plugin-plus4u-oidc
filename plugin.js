const OidcToken = require("./oidc-client");
const NodeCache = require("node-cache");
const Jwt = require("jws");
const secureStore = require("oidc-plus4u-vault/lib/securestore");
const fetch = require("node-fetch");
const https = require('node:https');
const crypto = require('node:crypto');

const alreadyRunningForTokenMap = {};

// In-memory (session-only) cache for prompted secrets. Not persisted to workspace.
const promptedSecretCache = new Map();

let TOKEN_GRACE_PERIOD_SECS = 5 * 60; //5 minutes

let oidcTokenCache = new NodeCache({ stdTTL: 60 * 60, checkperiod: 120 });

// Cache TTL for error results (prevents endless login retries on persistent config errors)
let ERROR_CACHE_TTL_SECS = 5 * 60; // 5 minutes

function cacheToken(token, identification) {
  let now = new Date();
  const decodedToken = Jwt.decode(token);
  if (decodedToken && decodedToken.payload) {
    let exp = new Date(decodedToken.payload.exp * 1000); //token exp is in seconds
    let cacheTtl = exp.getTime() - now.getTime() - TOKEN_GRACE_PERIOD_SECS * 1000;
    // If token is near-expiry (or already expired), don't cache it.
    if (cacheTtl > 0) {
      oidcTokenCache.set(identification, getTokenObject(token, exp), cacheTtl / 1000);
    } else {
      console.debug(`Token ${identification} is too close to expiration, skipping cache.`);
    }
  } else {
    console.log("decoding failed, token is not cached");
  }
}

function cacheErrorResult(identification, err) {
  const cachedAt = new Date();
  const message = safeErrorToString(err);
  oidcTokenCache.set(
    identification,
    {
      error: true,
      cachedAt,
      message,
      // keep shape similar enough so callers can inspect
      token: null,
      reuseLimit: cachedAt,
    },
    ERROR_CACHE_TTL_SECS
  );
}

function getTokenObject(token, exp) {
  let limit = exp.getTime() - 60 * 60 * 1000;
  return {
    token: token,
    reuseLimit: new Date(limit)
  }
}

function getHttpsAgent(validate) {
  return new https.Agent({
    rejectUnauthorized: validate,
  });
}

function safeErrorToString(err) {
  if (!err) return "Unknown error";
  if (typeof err === "string") return err;
  // Prefer the human-readable message
  let msg = err.message || String(err);
  // If it's an HTTP error message we built (includes status/body), keep it.
  // Redact obvious secrets if they accidentally appear.
  msg = msg.replace(/client_secret=([^&\s]+)/gi, "client_secret=***");
  msg = msg.replace(/"client_secret"\s*:\s*"[^"]+"/gi, '"client_secret":"***"');
  // Keep it short for UI fields
  if (msg.length > 500) msg = msg.slice(0, 500) + "...";
  return msg;
}

function shortHash(value) {
  if (!value) return "";
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 12);
}

function makeTokenId(cacheTag, oidcServer, infoPage, clientId, clientSecret, validate) {
  // Never put the raw clientSecret into the cache key (or logs). Use a short hash.
  const secretHash = clientSecret ? shortHash(clientSecret) : "";
  return `TOKEN:${cacheTag || "default"}-${oidcServer || "default"}-${infoPage || "default"}-${clientId || "default"}-${secretHash}-${validate}`;
}

// Unified formatting of user-visible outputs (Insomnia template tag result)
// Keep these short and consistent so they stand out in headers/bodies.
function formatTagMessage(kind, message) {
  const cleanKind = (kind || "status").toString().trim();
  const cleanMessage = (message || "").toString().trim();
  if (!cleanMessage) return `-- ${cleanKind} --`;
  return `-- ${cleanKind}: ${cleanMessage} --`;
}

function formatTokenDisabled() {
  return formatTagMessage("token disabled", "");
}

function formatTokenInProgress() {
  return formatTagMessage("token retrieval already in progress", "");
}

function formatCachedAt(date) {
  // We store Date objects in cache; still handle strings/numbers defensively.
  const d = date instanceof Date ? date : new Date(date);
  if (Number.isNaN(d.getTime())) return String(date);
  return d.toISOString();
}

function formatTokenCachedError(message, cachedAt) {
  const when = cachedAt ? formatCachedAt(cachedAt) : "unknown time";
  return formatTagMessage(`token error (cached ${when}, toggle the Disabled switch to refresh)`, `${message}`);
}

function formatTokenError(err) {
  return formatTagMessage("token error", safeErrorToString(err));
}

async function interactiveLogin(disabled, cacheTag, oidcServer, infoPage, clientId, clientSecret, validate) {
  console.debug(`Getting OIDC token from ${oidcServer}, infoPage: ${infoPage}, clientId: ${clientId}, validate certs: ${validate}`);
  const tokenId = makeTokenId(cacheTag, oidcServer, infoPage, clientId, clientSecret, validate);
  if (disabled) {
    console.debug(`Login is disabled for cacheTag ${cacheTag} and oidcServer ${oidcServer}, removing any cached token ${tokenId} and returning empty string.`);
    oidcTokenCache.del(tokenId);
    return formatTokenDisabled();
  }
  console.debug(`Login is active for cacheTag ${cacheTag} and oidcServer ${oidcServer}, cached token to be used ${tokenId}`);
  const cachedToken = oidcTokenCache.get(tokenId);
  if (cachedToken) {
    if (cachedToken.error) {
      return formatTokenCachedError(cachedToken.message || "Unknown error", cachedToken.cachedAt);
    }
    if (cachedToken.reuseLimit > new Date()) {
      // refreshToken + this.cacheToken(token, identification);
    }
    console.debug(`Using cached OIDC token for id ${tokenId}`, cachedToken);
    return cachedToken.token;
  }

  if (alreadyRunningForTokenMap[tokenId]) {
    console.debug(`The interactive login for token ${tokenId} is already running, skipping the processing`);
    return formatTokenInProgress();
  }

  alreadyRunningForTokenMap[tokenId] = true;
  try {
    const agent = getHttpsAgent(validate);

    const token = await OidcToken.interactiveLogin(oidcServer, infoPage, clientId, clientSecret, agent);
    console.debug(`Obtained OIDC token for tokenId ${tokenId}`, token);
    cacheToken(token, tokenId);
    return token;
  } catch (e) {
    console.error("Interactive OIDC login failed:", safeErrorToString(e));
    // Return something visible in Insomnia instead of empty string.
    cacheErrorResult(tokenId, e);
    return formatTokenError(e);
  } finally {
    alreadyRunningForTokenMap[tokenId] = false;
  }
}

async function interactiveLoginWithPrompt(
  context,
  disabled,
  cacheTag,
  oidcServer,
  infoPage,
  clientId,
  validate,
) {
  let usedSecret = null;

  const key = `${cacheTag || "default"}#${oidcServer || "default"}#${clientId || "default"}`;
  if (promptedSecretCache.has(key)) {
    usedSecret = promptedSecretCache.get(key);
  } else if (!disabled) {
    // Only prompt when active.
    usedSecret = await context.app.prompt('OIDC client secret', {
      label: `Client Secret for ${oidcServer} - ${clientId} (${cacheTag})`,
    });
    if (usedSecret) {
      promptedSecretCache.set(key, usedSecret);
    }
  }

  if (!usedSecret) {
    return formatTagMessage("Undefined client_secret", "No Client Secret defined, please use the template for the first time to provide it via a prompt.");
  }

  return await interactiveLogin(disabled, cacheTag, oidcServer, infoPage, clientId, usedSecret, validate);
}

module.exports.templateTags = [
  {
    name: "uuPersonPlus4uOidcToken",
    displayName: "Token from oidc.plus4u.net",
    description: "Get identity token from oidc.plus4u.net",
    args: [
      {
        displayName: "Mode",
        type: "enum",
        defaultValue: "production",
        options: [
          { displayName: "Production", value: "production" },
          { displayName: "Development", value: "development" }
        ],
        help: "Select the environment."
      },
      {
        displayName: "Disabled (also check/uncheck to refresh a cached result)",
        type: "boolean",
        defaultValue: false,
        help: `If checked, this configuration is disabled. You can also check/uncheck this to refresh a cached result`
      },
    ],
    async run(context, mode, disabled) {
      if (mode === "development") {
        const config = OidcToken.ENVIRONMENTS.development;
        return await interactiveLogin(disabled, "development", config.oidcServer, config.infoPage, config.clientId, config.clientSecret, true);
      }
      return await interactiveLogin(disabled);
    }
  },
  {
    name: "uuPersonCustomOidcToken",
    displayName: "Token from a custom uuOIDC server",
    description: "Get identity token from a custom uuOIDC server",
    args: [
      {
        displayName: "Disabled (also check/uncheck to refresh a cached result)",
        type: "boolean",
        defaultValue: false,
        help: `If checked, this configuration is disabled. You can also check/uncheck this to refresh a cached result`
      },
      {
        displayName: "Cache Tag",
        type: "string",
        defaultValue: "defaultTag",
        help: `The tag which can be used to distinguish between several cached values.`
      },
      {
        displayName: "OIDC Server",
        type: "string",
        defaultValue: "--fill-in--",
        placeholder: "https://<gateway>/uu-oidc-maing02/<awid>/oidc",
        help: `URL of the OIDC server (typical format is https://<gateway>/uu-oidc-maing02/<awid>/oidc).`
      },
      {
        displayName: "OIDC Info Page",
        type: "string",
        defaultValue: "--fill-in--",
        placeholder: "https://<gateway>/uu-identitymanagement-maing01/<awid>/showAuthorizationCode",
        help: `URL of the OIDC info page (typically it is uuIdentityManagement route: https://<gateway>/uu-identitymanagement-maing01/<awid>/showAuthorizationCode.`
      },
      {
        displayName: "Client ID",
        type: "string",
        defaultValue: "",
        help: `client_id of the OIDC client.`
      },
      {
        displayName: "Validate certificates",
        type: "boolean",
        defaultValue: true,
        help: `If checked, validate SSL certificates for API requests.`
      }
    ],
    async run(context, disabled, cacheTag, oidcServer, infoPage, clientId, validate = false) {
      console.debug("Running with context", context);
      console.debug("Running with context purpose", context.context.getPurpose());
      return await interactiveLoginWithPrompt(
        context,
        disabled,
        cacheTag,
        oidcServer,
        infoPage,
        clientId,
        validate,
      );
    }
  },
  {
    name: "uuEePlus4uOidcToken",
    displayName: "Token from oidc.plus4u.net for uuEE",
    description: "Get identity token from oidc.plus4u.net as defined uuEE",
    accessCodesStore: new Map(),
    vaultPassword: null,
    args: [
      {
        displayName: "Prompt user identification",
        type: "string",
        help: `Identification to distinguish prompts for multiple different users. Please note that this information is shared accross the application in all
      prompts. So in case that you have multiple prompts with the same identification, they will share the token and access codes.`
      },
      {
        displayName: "OIDC Server",
        type: "string",
        defaultValue: "https://uuidentity.plus4u.net/uu-oidc-maing02/bb977a99f4cc4c37a2afce3fd599d0a7/oidc",
        help: `URL of the OIDC server.`
      },
      {
        displayName: "Token scope",
        type: "string",
        defaultValue: "openid https:// http://localhost",
        help: `URL of the OIDC server.`
      },
      {
        displayName: "Validate certificates",
        type: "boolean",
        defaultValue: true,
        help: `If checked, validate SSL certificates for API requests.`
      }
    ],

    async login(accessCode1, accessCode2, oidcServer, scope, validate) {
      if (accessCode1.length === 0 || accessCode2.length === 0) {
        throw `Access code cannot be empty. Ignore this error for "Prompt ad-hoc".`;
      }

      const agent = getHttpsAgent(validate);
      let tokenEndpoint = await this.getTokenEndpoint(oidcServer, agent);

      if (tokenEndpoint.startsWith("https://login.microsoftonline.com/")) {
        return this._loginToAzure(accessCode1, accessCode2, scope, tokenEndpoint, agent, oidcServer);
      } else {
        return this._loginToUuOidc(accessCode1, accessCode2, scope, tokenEndpoint, agent, oidcServer);
      }
    },

    async _performTokenRequest(tokenEndpoint, credentials, agent) {
      let headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      };

      const body = new URLSearchParams();
      Object.entries(credentials).forEach(([k, v]) => body.append(k, String(v)));

      const res = await fetch(tokenEndpoint, {
        method: "POST",
        headers: headers,
        body: body.toString(),
        agent: agent
      });
      return await res.json();
    },

    async _loginToAzure(accessCode1, accessCode2, scope, tokenEndpoint, agent, oidcServer) {
      let credentials = {
        username: accessCode1,
        password: accessCode2,
        grant_type: "password",
        scope,
        client_id: scope.replace(/^api:\/\//, "").replace(/\/.*/, "")
      };

      let resp = await this._performTokenRequest(tokenEndpoint, credentials, agent);
      if (resp.error) {
        throw `Cannot login to OIDC server on ${oidcServer}. Probably invalid combination of Access Code 1 and Access Code 2. Error: ${resp.error_description || resp.error}`;
      }
      return resp.id_token;
    },

    async _loginToUuOidc(accessCode1, accessCode2, scope, tokenEndpoint, agent, oidcServer) {
      let credentials = {
        accessCode1,
        accessCode2,
        grant_type: "password",
        scope
      };

      let resp = await this._performTokenRequest(tokenEndpoint, credentials, agent);
      if (resp && resp.uuAppErrorMap && Object.keys(resp.uuAppErrorMap).length > 0) {
        throw `Cannot login to OIDC server on ${oidcServer}. Probably invalid combination of Access Code 1 and Access Code 2.`;
      }
      return resp.id_token;
    },

    async getTokenEndpoint(oidcServer, agent) {
      let oidcServerConfigUrl = oidcServer + "/.well-known/openid-configuration";
      const response = await fetch(oidcServerConfigUrl, {
        agent: agent
      });
      const oidcConfig = await response.json();

      const isAzure = oidcServer.startsWith("https://login.microsoftonline.com/");
      const hasError = isAzure ? oidcConfig.error : (oidcConfig.uuAppErrorMap && Object.keys(oidcConfig.uuAppErrorMap).length > 0);

      if (hasError) {
        throw `Cannot get configuration of OIDC server on ${oidcServer}. Probably invalid URL.`;
      }
      return oidcConfig.token_endpoint;
    },

    async loginDirectly(context, identification, oidcServer, oidcScope, validate, cacheKey) {
      let ac1;
      let ac2;
      if (this.accessCodesStore.get(cacheKey)) {
        ac1 = this.accessCodesStore.get(cacheKey).accessCode1;
        ac2 = this.accessCodesStore.get(cacheKey).accessCode2;
      } else {
        if (secureStore.exists()) {
          if (!this.vaultPassword) {
            let password;
            password = await context.app.prompt('OIDC vault password', { label: "OIDC vault password", inputType: "password" });
            if (password) {
              try {
                secureStore.read(password);
                this.vaultPassword = password;
              } catch (e) {
                console.error("Invalid vault password.");
                console.error(e);
              }
            }
          }
          if (this.vaultPassword) {
            let vault = secureStore.read(this.vaultPassword);
            if (vault[identification]) {
              ac1 = vault[identification].ac1;
              ac2 = vault[identification].ac2;
            }
          }
        }
        if (!ac1) {
          ac1 = await context.app.prompt('Access code 1', { label: "Access Code 1 for user " + identification, inputType: "password" });
          ac2 = await context.app.prompt('Access code 2', { label: "Access Code 2 for user " + identification, inputType: "password" });
        }
      }

      let token = await this.login(ac1, ac2, oidcServer, oidcScope, validate);
      this.accessCodesStore.set(cacheKey, { accessCode1: ac1, accessCode2: ac2 });

      return token;
    },

    async run(context, identification, oidcServer, tokenScope, validate = true) {
      const oidcScope = tokenScope ? tokenScope : "openid https:// http://localhost";
      // Cache key must include multiple attributes to correctly handle switching of environments and workspaces
      const cacheKey = identification + "#" + oidcServer + "#" + oidcScope + "#" + context.meta.workspaceId;
      let token = oidcTokenCache.get(cacheKey)?.token;
      if (!token) {
        token = await this.loginDirectly(context, identification, oidcServer, oidcScope, validate, cacheKey);
        cacheToken(token, cacheKey, false);
      }
      return token;
    }

  }
];
