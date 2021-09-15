const OidcToken = require("./oidc-client");
const NodeCache = require("node-cache");
const Jwt = require("jws");
const secureStore = require("oidc-plus4u-vault/lib/securestore");
const fetch = require("node-fetch");
const HttpsProxyAgent = require('https-proxy-agent');

let isAlreadyRunning = false;

const MY_TOKEN = "myToken";

let oidcTokenCache= new NodeCache({ stdTTL: 60 * 60, checkperiod: 120 });

function cacheToken(token, identification) {
  const decodedToken = Jwt.decode(token);
  if (decodedToken && decodedToken.payload) {
    let now = new Date();
    let exp = new Date(decodedToken.payload.exp * 1000); //token exp is in seconds
    let cacheTtl = exp.getTime() - now.getTime() - 15 * 60 * 1000;
    oidcTokenCache.set(identification, getTokenObject(token, exp), cacheTtl / 1000);
  } else {
    console.log("decoding failed, storing token without additional info");
    oidcTokenCache.set(identification, getTokenObject(token, exp));
  }
}

function getTokenObject(token, exp){
  let limit = exp.getTime - 60*60*1000;
  return {
    token: token,
    reuseLimit: new Date(limit)
  }
}

module.exports.templateTags = [
  {
    name: "uuPersonPlus4uOidcToken",
    displayName: "Token from oidc.plus4u.net",
    description: "Get identity token from oidc.plus4u.net",

    async run(context, oidcServer) {
      const cachedToken = oidcTokenCache.get(MY_TOKEN);
      if (cachedToken) {
        if(cachedToken.reuseLimit > new Date()){
          //refreshToken + this.cacheToken(token, identification);
        }
        return cachedToken.token;
      }
      if (isAlreadyRunning) {
        return "";
      }
      isAlreadyRunning = true;
      try {
        const token = await OidcToken.interactiveLogin();
        cacheToken(token, MY_TOKEN);
        return token;
      }catch (e) {
        console.error(e);
      }finally {
        isAlreadyRunning = false;
      }
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
      }
    ],

    async login(accessCode1, accessCode2, oidcServer, scope, proxy) {
      if (accessCode1.length === 0 || accessCode2.length === 0) {
        throw `Access code cannot be empty. Ignore this error for "Prompt ad-hoc".`;
      }

      let tokenEndpoint = await this.getTokenEndpoint(oidcServer, proxy);

      let credentials = {
        accessCode1,
        accessCode2,
        grant_type: "password",
        scope
      };

      const res = await fetch(tokenEndpoint, this.getLoginDtoIn(credentials, proxy));
      let resp = await res.json();
      if (Object.keys(resp.uuAppErrorMap).length > 0) {
        throw `Cannot login to OIDC server on ${oidcServer}. Probably invalid combination of Access Code 1 and Access Code 2.`;
      }
      return resp.id_token;
    },

    getLoginDtoIn(credentials, proxy) {
      let loginDtoIn = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json"
        },
        body: JSON.stringify(credentials)
      };
      return proxy ? {...loginDtoIn, agent: new HttpsProxyAgent(proxy)} : loginDtoIn
    },

    async getTokenEndpoint(oidcServer, proxy) {
      let oidcServerConfigUrl = oidcServer + "/.well-known/openid-configuration";
      const response = await fetch(oidcServerConfigUrl, this.getOpenIdConfigurationDtoIn(oidcServer, proxy));
      const oidcConfig = await response.json();
      if (Object.keys(oidcConfig.uuAppErrorMap).length > 0) {
        throw `Cannot get configuration of OIDC server on ${oidcServer}. Probably invalid URL.`;
      }
      return oidcConfig.token_endpoint;
    },

    getOpenIdConfigurationDtoIn(oidcServer, proxy) {
      return proxy ? {agent: new HttpsProxyAgent(proxy)} : {};
    },

    async loginDirectly(context, identification, oidcServer, oidcScope, cacheKey) {
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

      let token = await this.login(ac1, ac2, oidcServer, oidcScope, context.context.proxy);
      this.accessCodesStore.set(cacheKey, {accessCode1: ac1, accessCode2: ac2});

      return token;
    },

    async run(context, identification, oidcServer, tokenScope) {
      const oidcScope = tokenScope ? tokenScope : "openid https:// http://localhost";
      // Cache key must include multiple attributes to correctly handle switching of environments and workspaces 
      const cacheKey = identification + "#" + oidcServer + "#" + oidcScope + "#" + context.meta.workspaceId;
      let token = oidcTokenCache.get(cacheKey)?.token;
      if (!token) {
        token = await this.loginDirectly(context, identification, oidcServer, oidcScope, cacheKey);
        cacheToken(token, cacheKey);
      }
      return token;
    }
  }
];
