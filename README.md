# bWAPP - Fixed Security Vulnerabilities

## Original Application

bWAPP (buggy web application) is a deliberately insecure web application for security testing.

## Vulnerabilities Fixed

### Critical Vulnerabilities (Fixed)

| #  | Vulnerability                  | File                       | Severity |
| -- | ------------------------------ | -------------------------- | -------- |
| 1  | Command Injection              | bof_1.php                  | Critical |
| 2  | Command Injection              | commandi.php               | Critical |
| 3  | Command Injection              | commandi_blind.php         | Critical |
| 4  | Code Injection (eval)          | phpi.php                   | Critical |
| 5  | SQL Injection (Login Bypass)   | sqli_3.php                 | Critical |
| 6  | SQL Injection (Authentication) | sqli_16.php                | Critical |
| 7  | SQL Injection                  | sqli_1.php                 | High     |
| 8  | SSRF                           | ba_forgotten.php           | High     |
| 9  | SSRF                           | user_extra.php             | High     |
| 10 | Path Traversal                 | restrict_folder_access.php | High     |

## Fixes Applied

* SQL Injection: Converted to prepared statements
* Command Injection: Added input validation with escapeshellarg()
* Code Injection: Replaced eval() with whitelist approach
* SSRF: Added host validation and hardcoded base URLs
* Path Traversal: Added file whitelist and path validation

## Testing Results

* OWASP ZAP: Critical vulnerabilities eliminated
* Semgrep: 58 findings → 43 findings (26% reduction)
* Manual testing: All fixes verified

## Author

MUNGUFENI MARK JOEL
2025/HD05/31216U
2500731216

5th MAY 2026
