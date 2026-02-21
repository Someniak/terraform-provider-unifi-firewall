# Changelog

All notable changes to this project will be documented in this file.

## [0.3.2] - 2026-02-21

### Fixed
- Improved handling of `allow_return_traffic` in firewall policies to prevent persistent diffs.
- Corrected default values for optional filters (`Description`, `IPsecFilter`, `ConnectionStateFilter`) in state mapping.
- Fixed mapping of traffic filters when reading from the UniFi API.

## [0.3.1] - 2026-02-21

### Fixed
- Stability fixes for optional attributes to reduce unnecessary diffs.

## [0.3.0] - 2026-02-21

### Added
- Initial support for complex firewall policies with combined filters.
- Support for `unifi_fw` and `unifi_dns` resource naming.
