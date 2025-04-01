# WSO2 Identity Server - Have I Been Pwned Password Validator

A password validator extension for WSO2 Identity Server that integrates with the [Have I Been Pwned (HIBP)](https://haveibeenpwned.com/) service to check if passwords have been exposed in data breaches.

## Overview

This extension enhances the security of WSO2 Identity Server by preventing users from setting passwords that have been found in known data breaches. The validator leverages the Have I Been Pwned API, which employs a k-anonymity model to securely check passwords without sending the actual password over the network.

## Features

- Validates user passwords against the HIBP database of compromised passwords
- Uses secure k-anonymity model (only the first 5 characters of the password hash are sent to the API)
- Configurable through the WSO2 Identity Server management console
- Supports multi-tenancy
- Provides API key configuration for authenticated access to the HIBP service

## Prerequisites

- WSO2 Identity Server (tested with version 5.10.0+)
- Maven 3.x
- Java 1.8 or higher
- A valid API key for the HIBP service (obtain from [haveibeenpwned.com](https://haveibeenpwned.com/API/Key))

## Installation

1. Build the extension using Maven:
   ```bash
   mvn clean install
   ```

2. Copy the generated JAR file to the WSO2 Identity Server:
   ```
   cp target/org.wso2.identity.password.validator.hibp-1.0.0.jar <IS-HOME>/repository/components/dropins/
   ```

3. Add the following configuration to `<IS-HOME>/repository/conf/deployment.toml` to allow access to the HIBP endpoint:
   ```
   [[resource.access_control]]
   context = "(.*)/hibp(.*)"
   secure = false
   http_method = "all"
   ```
   
   **Note:** For versions of WSO2 IS using `identity.xml.j2`, add this instead:
   ```
   <Resource context="(.*)/hibp(.*)" secured="false" http-method="all"/>
   ```

4. Restart the WSO2 Identity Server.

## Configuration

1. Log into the WSO2 Identity Server Management Console.
2. Navigate to **Main** > **Identity** > **Identity Providers** > **Resident** > **Password Policies**.
3. Find the **Pwned Passwords** section.
4. Enable the HIBP password validator by checking the box.
5. Enter your HIBP API key in the designated field.
6. Save your changes.

## How it Works

When a user attempts to create or change a password, the following process occurs:

1. The password is hashed using SHA-1 (as required by the HIBP API).
2. Only the first 5 characters of the hash are sent to the HIBP API.
3. The API returns a list of hash suffixes (remaining 35 characters) that match the provided prefix.
4. The extension checks if the full hash of the user's password matches any in the returned list.
5. If a match is found, the password is rejected as it has appeared in known data breaches.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

## Support

For questions or issues, please create an issue in the [GitHub repository](https://github.com/wso2-extensions/identity-password-validator-hibp/issues).
