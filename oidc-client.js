"use strict";

const http = require("http");
const Url = require('url-parse');
const open = require("open");
const fetch = require("node-fetch");

const OAUTH_CODE = "code";
const DEFAULT_OIDC_TENANT = "bb977a99f4cc4c37a2afce3fd599d0a7";
const DEFAULT_OIDC_BASE_URI = "https://uuidentity.plus4u.net/uu-oidc-maing02";
const OIDC_WELL_KNOWN_DISCOVERY_PATH = ".well-known/openid-configuration";
const OAUTH_GRANT_TYPE = "grant_type";
const OAUTH_GRANT_TYPE_CODE = "authorization_code";
const OAUTH_SCOPE = "scope";
const OAUTH_SCOPE_OPENID = "openid";
const OAUTH_CLIENT_ID = "client_id";
const OAUTH_CLIENT_SECRET = "client_secret";
const OAUTH_REDIRECT_URI = "redirect_uri";
const OAUTH_RESPONSE_TYPE = "response_type";
const DEFAULT_CLIENT_ID = "F64b643R05xQ62696875W1j2";
const DEFAULT_CLIENT_SECRET = "2u1q5KU2Z0Bs5SErmYVwM053+zyKDxT7QLU2Q7Rr7nn5t5%Bt80px8mf3$s16FdK";
const DEFAULT_AUDIENCE = "https:// http://localhost";
const DEFAULT_INFO_PAGE = "https://uuidentity.plus4u.net/uu-identitymanagement-maing01/a9b105aff2744771be4daa8361954677/showAuthorizationCode";

class OidcClient {

  static async interactiveLogin(oidcServer, infoPage, clientId, clientSecret, agent) {
    console.debug(`interactiveLogin called with params:`, {oidcServer, infoPage, clientId});
    const usedOidcServer = oidcServer || OidcClient.getOidcUri();
    let [code, serverPort] = await OidcClient.getAuthorizationCode(usedOidcServer, infoPage, clientId, agent);
    let token = await OidcClient.grantAuthorizationCodeToken(code, serverPort, clientId, clientSecret, agent, usedOidcServer);

    if (!token.id_token) {
      console.error("Unexpected response from OIDC server, no id_token present:", token);
      return "error";
      //throw new Error("Authentication failed, no id_token returned from OIDC server.");
    }
    return token.id_token;
  }

  static isInteractiveLoginAvailable() {
    // TODO
    return true;
  }

  static async getAuthorizationCode(oidcServer, infoPage, clientId, agent) {
    console.debug(`getAuthorizationCode called with params:`, {oidcServer, infoPage, clientId});
    let metadata = await OidcClient.getMetadata(oidcServer, false, agent);
    const usedClientId = clientId || DEFAULT_CLIENT_ID;
    const usedInfoPage = infoPage || DEFAULT_INFO_PAGE;
    return await new Promise((resolve, reject) => {
      // Start local server to handle auth callback
      let server = http.createServer((req, res) => {
        //let query = url.parse(req.url, true).query;
        console.debug("Local server received request with url", req.url);
        let query = new Url(req.url, null, true).query;
        let code = query[OAUTH_CODE];
        let redirectUri = usedInfoPage;
        redirectUri += `?clientId=${usedClientId}`;
        if (code) {
          console.debug(`Received authorization code from OIDC server, redirecting to ${redirectUri}.`);
          resolve([code, server.address().port]);
          res.writeHead(302, {"Location": redirectUri});
        } else {
          let uuAppErrorMap = query["uuAppErrorMap"];
          console.error(`No access token code returned from OIDC server:`, uuAppErrorMap);
          reject(new Error(`No access token code returned from OIDC server: ${uuAppErrorMap}`));
          redirectUri += `&uuAppErrorMap=${uuAppErrorMap}`;
          res.writeHead(302, {"Location": redirectUri});
        }
        res.end(() => {
          // Close server after response is handled
          server.close();
        });
      });
      server.listen(0);
      // Open browser to initialize auth process
      let authzUri = metadata["authorization_endpoint"];
      authzUri += `?${OAUTH_CLIENT_ID}=${usedClientId}`;
      authzUri += `&${OAUTH_REDIRECT_URI}=http://localhost:${server.address().port}`;
      authzUri += `&${OAUTH_RESPONSE_TYPE}=${OAUTH_CODE}`;
      authzUri += `&${OAUTH_SCOPE}=${OAUTH_SCOPE_OPENID}${encodeURIComponent(" " + DEFAULT_AUDIENCE)}`;

      console.debug("Opening browser with authzUri:", authzUri);
      open(authzUri);
    });
  }

  static async getMetadata(providerUri = null, refresh = false, agent) {
    console.debug("getMetadata called with params:", {providerUri});
    if (providerUri === null) {
      // TODO Handle trailing slashes from configuration parameters
      providerUri = this.getOidcUri();
    }

    let discoveryUri = `${providerUri}/${OIDC_WELL_KNOWN_DISCOVERY_PATH}`;
    console.debug("discoveryUri for getMetadata", discoveryUri);
    const response = await fetch(discoveryUri, {agent: agent});
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`OIDC discovery failed (${response.status} ${response.statusText}) at ${discoveryUri}${body ? `: ${body}` : ""}`);
    }
    const result = await response.json();
    console.debug("discoveryUri call returned result", result);
    return result;
  }

  static async grantAuthorizationCodeToken(authorizationCode, serverPort, clientId, clientSecret, agent, oidcServer) {
    console.debug(`grantAuthorizationCodeToken called with params:`, {authorizationCode, serverPort, clientId, oidcServer});
    const usedClientId = clientId || DEFAULT_CLIENT_ID;
    const usedClientSecret = clientSecret || DEFAULT_CLIENT_SECRET;

    let params = {};
    params[OAUTH_GRANT_TYPE] = OAUTH_GRANT_TYPE_CODE;
    params[OAUTH_CODE] = authorizationCode;
    params[OAUTH_CLIENT_ID] = usedClientId;
    params[OAUTH_CLIENT_SECRET] = usedClientSecret;
    params[OAUTH_SCOPE] = `${OAUTH_SCOPE_OPENID} ${DEFAULT_AUDIENCE}`;
    params[OAUTH_REDIRECT_URI] = `http://localhost:${serverPort}`;
    return await OidcClient.grantToken(params, agent, oidcServer);
  }

  static async grantToken(params, agent, oidcServer) {
    let metadata = await OidcClient.getMetadata(oidcServer, false, agent);
    let grantTokenUri = metadata["token_endpoint"];

    // OAuth2/OIDC token endpoint is typically x-www-form-urlencoded.
    let headers = {};
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    headers["Accept"] = "application/json";

    const body = new URLSearchParams();
    Object.entries(params || {}).forEach(([k, v]) => {
      if (v !== undefined && v !== null) body.append(k, String(v));
    });

    try {
      console.debug(`grantToken - calling  grantTokenUri ${grantTokenUri} with params:`, params);
      const res = await fetch(grantTokenUri, {
        agent: agent,
        method: "POST",
        headers: headers,
        body: body.toString(),
      });

      const contentType = res.headers.get("content-type") || "";
      const payload = contentType.includes("application/json") ? await res.json() : await res.text();

      if (!res.ok) {
        throw new Error(`Token request failed (${res.status} ${res.statusText}) at ${grantTokenUri}: ${typeof payload === "string" ? payload : JSON.stringify(payload)}`);
      }

      return payload;
    } catch (e) {
      console.error(`grantToken - authentication failed:`, e);
      throw e;
    }
  }

  static getOidcUri() {
    let oidcUri = `${DEFAULT_OIDC_BASE_URI}/${DEFAULT_OIDC_TENANT}/oidc`;
    return oidcUri;
  }
}

module.exports = OidcClient;
