# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Changed

## [0.3.0] - 2025-01-07
- possibility to disable certficate chain validity

## [0.2.7] - 2021-07-20
- replaced library "url" for "url-parse"

## [0.2.6] - 2021-05-03

### Changed
- Added definition of scope in GUI


## [0.2.5] - 2021-05-03

### Changed
- Fixed cache key (added scope, oidc server and workspace id)
- Added possibility to define custom scope


## [0.2.4] - 2021-04-19

### Changed
- Fixed loading of token for *uuPersonPlus4uOidcToken* - sometimes token was not loaded in time

## [0.2.3] - 2020-09-05

### Changed
- Fixed default configuration for the *uuEePlus4uOidcToken*
- Fixed login trough *uuEePlus4uOidcToken*

## [0.2.2] - 2020-06-04

### Changed
- Replaced library Got with node-fetch. Got had problems on some systems

## [0.2.1] - 2020-04-10

### Changed
- Updated versions of libraries

## [0.2.0] - 2020-04-09

### Changed
- Changed default OIDC provider. Current is OIDCg02.
- Updated versions of underlayer libraries


## [0.1.3] - 2019-01-25

### Changed
- Updated dependency on *oidc-plus4u-vault*

## [0.1.2] - 2019-01-25
### Added
- Integrated with *oidc-plus4u-vault*. It enables storing credentials for uuEE on local machine without keeping credentials in insomnia export
- New tag *uuEePlus4uOidcToken*. It enables authentication for uuEE (credentials asked once during insomnia running, or loaded from *oidc-plus4u-vault*)
- Enhanced original tag *uuPersonPlus4uOidcToken*. It supports configuring different OIDC.

### Changed

### Removed


## 0.1.1 - initial public release

