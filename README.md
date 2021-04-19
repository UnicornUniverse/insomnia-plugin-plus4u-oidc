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

# Features
## *uuPersonPlus4uOidcToken*
- easy Insomnia authentication against <https://oidc.plus4.net> (can be changed in tag configuration)
- no configuration needed - token is loaded by opening window in default browser
- cache (all valid tokens are cached, the TTL is 15 minutes before token expiration)

## *uuEePlus4uOidcToken*
- easy Insomnia authentication against <https://oidc.plus4.net> (can be changed in tag configuration)
- configuration when first needed, keeps credentials for uuEE during insomnia running
- credentials can be stored in *oidc-plus4u-vault*
- tokens are automatically reloaded when expired

# Limitations
- none