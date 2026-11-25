# Security policy

## Supported version

Only the latest release of SUNavigator receives fixes. See the [releases](https://github.com/cagdaskarabag/su_navigator/releases).

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private report: open the **Security** tab of this repository and choose **Report a vulnerability**. Include the SUNavigator and Splunk versions, the role you used, the steps, and what you saw. Do not include passwords, tokens or real log data.

Expect an answer in a few days. The project is maintained by one person, so there is no fixed response time.

## What the app trusts

The trust boundaries, roles and access rules are in [docs/SECURITY.md](../docs/SECURITY.md). In short: the app changes nothing in Splunk until a user with the right role confirms it, deployed searches are disabled by default, and every change is written to a hash-chained audit trail.
