const OidcToken = require("./oidc-client");
const NodeCache = require("node-cache");
const Jwt = require("jws");
const secureStore = require("oidc-plus4u-vault/lib/securestore");
const fetch = require("node-fetch");
const https = require('https');
const crypto = require('crypto');

const alreadyRunningForTokenMap = {};

let TOKEN_GRACE_PERIOD_SECS = 5 * 60; //5 minutes

let oidcTokenCache= new NodeCache({ stdTTL: 60 * 60, checkperiod: 120 });

// Cache TTL for error results (prevents endless login retries on persistent config errors)
let ERROR_CACHE_TTL_SECS = 5*60; // 5 minutes

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
  } else  {
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

function getTokenObject(token, exp){
  let limit = exp.getTime() - 60*60*1000;
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

module.exports.templateTags = [
  {
    name: "uuPersonPlus4uOidcToken",
    displayName: "Token from oidc.plus4u.net",
    description: "Get identity token from oidc.plus4u.net",
    args: [
      {
        displayName: "Disabled (also check/uncheck to refresh a cached result)",
        type: "boolean",
        defaultValue: false,
        help: `If checked, this configuration is disabled. You can also check/uncheck this to refresh a cached result`
      },
    ],
    async run(context, disabled) {
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
        displayName: "Client Secret",
        type: "string",
        defaultValue: "",
        help: `client_secret of the OIDC client.`
      },
      {
        displayName: "Validate certificates",
        type: "boolean",
        defaultValue: true,
        help: `If checked, validate SSL certificates for API requests.`
      }
    ],
    async run(context, disabled, cacheTag, oidcServer, infoPage, clientId, clientSecret, validate = false) {
      console.debug("Running with context", context);
      console.debug("Running with context purpose", context.context.getPurpose());
      return await interactiveLogin(disabled, cacheTag, oidcServer, infoPage, clientId, clientSecret, validate);
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

      let credentials = {
        accessCode1,
        accessCode2,
        grant_type: "password",
        scope
      };

      let headers = {};
      // Token endpoints are often strict about x-www-form-urlencoded.
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      headers["Accept"] = "application/json";

      const body = new URLSearchParams();
      Object.entries(credentials).forEach(([k, v]) => body.append(k, String(v)));

      const res = await fetch(tokenEndpoint, {
        method: "POST",
        headers: headers,
        body: body.toString(),
        agent: agent
      });
      let resp = await res.json();
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
      if (oidcConfig && oidcConfig.uuAppErrorMap && Object.keys(oidcConfig.uuAppErrorMap).length > 0) {
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
            password = await context.app.prompt('OIDC vault password', {label: "OIDC vault password", inputType: "password"});
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
          ac1 = await context.app.prompt('Access code 1', {label: "Access Code 1 for user " + identification, inputType: "password"});
          ac2 = await context.app.prompt('Access code 2', {label: "Access Code 2 for user " + identification, inputType: "password"});
        }
      }

      let token = await this.login(ac1, ac2, oidcServer, oidcScope, validate);
      this.accessCodesStore.set(cacheKey, {accessCode1: ac1, accessCode2: ac2});

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
