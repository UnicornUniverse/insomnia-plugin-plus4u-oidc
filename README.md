# insomnia-plugin-plus4u-oidc

This Insomnia plugin enables easy authentication againsts [https://uuidentity.plus4u.net/](https://uuidentity.plus4u.net/) (it can be changed in plugin configuration).

[Changelog](CHANGELOG.md)

# Installation

You can either install the plugin from <https://www.npmjs.com/package/insomnia-plugin-plus4u-oidc> or you can clone the git repository to Insomnia plugin folder. You can find more information at <https://support.insomnia.rest/article/26-plugins>.

# Update

Just install plugin again. New version replaces the old version.

# How to use ?

The plugin register [Template Tag](https://support.insomnia.rest/article/40-template-tags) with name **Token from oidc.plus4u.net** (*uuPersonPlus4uOidcToken*).
You can use this template tag anywhere you can use environment variable (even in the environment configuration).

Another tag is **Token from oidc.plus4u.net for uuEE** (*uuEePlus4uOidcToken*) it enables usage of uuEE - user is asked for credentials (keeps it during insomnia running), or user is asked with vault password and uses credentials from *oidc-plus4u-vault*

# Features and Configuration

## 1. Token from oidc.plus4u.net (*uuPersonPlus4uOidcToken*)
Use this tag for standard user authentication against the default Plus4U production environment.

- Easy Insomnia authentication against <https://oidc.plus4.net>
- No configuration needed - token is loaded by opening window in default browser
- Caching: all valid tokens are cached, the TTL is 5 minutes before token expiration

**Configuration:**
| Option | Description |
| :--- | :--- |
| **Disabled** | If checked, the tag returns a disabled message. Toggle this off/on to force a refresh. |

---

## 2. Token from a custom uuOIDC server (*uuPersonCustomOidcToken*)
Use this tag when you need to authenticate against a specific gateway or non-production environment.

- Interactive (browser-based) login for a **custom uuOIDC server**
- **Client Secret Handling**: The client secret is entered via a **password prompt** on first use and then kept **only in memory** for the current Insomnia session.

**Configuration:**
| Option | Description |
| :--- | :--- |
| **Disabled** | If checked, the tag returns a disabled message. Toggle this off/on to force a refresh. |
| **Cache Tag** | A unique string to distinguish between different cached sessions (e.g., "dev", "test"). |
| **OIDC Server** | The full URL of the OIDC server endpoint.<br>Example: `https://<gateway>/uu-oidc-maing02/<awid>/oidc` |
| **OIDC Info Page** | The URL where the browser redirects after login.<br>Example: `https://<gateway>/uu-identitymanagement-maing01/<awid>/showAuthorizationCode` |
| **Client ID** | The `client_id` of your application registered in the OIDC server. |
| **Validate certificates** | Uncheck this if you are using self-signed certificates (e.g., localhost). |

---

## 3. Token from oidc.plus4u.net for uuEE (*uuEePlus4uOidcToken*)
Use this tag for service account (uuEE) authentication.

- Configuration when first needed, keeps credentials for uuEE during insomnia running
- Credentials can be stored in *oidc-plus4u-vault*
- Tokens are automatically reloaded when expired

**Configuration:**
| Option | Description |
| :--- | :--- |
| **Prompt user identification** | A label to distinguish different uuEE accounts (e.g., "my-bot"). Use the same label to share prompted credentials across requests. |
| **OIDC Server** | Defaults to production. Change if targeting a different environment. |
| **Token scope** | The scope to request. Default is usually sufficient (`openid https:// http://localhost`). |
| **Validate certificates** | Enable/disable SSL validation. |

# Troubleshooting

- **Token not updating?**
  Valid tokens are cached for 55 minutes (or until 5 minutes before expiry). To force a refresh, open the tag configuration, check **Disabled**, close it, and then uncheck **Disabled**.

- **"Token error (cached...)"**
  If a login fails, the error is cached for 5 minutes. This prevents Insomnia from opening 100 browser tabs if you have 100 requests using the tag. Use the **Disabled** toggle trick above to clear the error immediately.

- **Client Secret Prompt**
  If you need to change a client secret (for `uuPersonCustomOidcToken`), restart Insomnia to clear the in-memory cache.