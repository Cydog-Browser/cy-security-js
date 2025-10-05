# Cydog Browser CySecurity.js
This is a free-to-use javascript drop-in to secure your website. It helps protect your web pages from hackers and hides itself to prevent reverse engineering attempts.

## Installation & Implementation
1. Download cysecurity.js
2. Add to web project (e.g., `/js/security/cysecurity.js`)
3. Include in your HTML **before any other scripts**:
```html
<head>
  <!-- Existing meta tags -->
  <!-- Existing Content Security Policy Meta Tag -->
  <script id="cysecurity" src="/js/security/cysecurity.js"></script>
</head>
```
4. Insert a CSP Meta Tag with customized list of domains
```html
<head>
  <meta http-equiv="Content-Security-Policy" content="default-src 'self' https://domain-that-gets-to-make-requests.com https://domain-that-gets-to-make-requests-2.com https://domain-that-gets-to-make-requests-3.com;">
  <!-- Existing cysecurity.js tag -->
</head>
```

## Core Protections
| Feature | Protection Level | Impact |
|---------|------------------|--------|
| **Input Sanitization** | Critical | Neutralizes `< > " ' &` characters |
| **CSP Recheck** | Critical | Auto-blocks non-CSP domains |
| **Certificate Validation** | High | Verifies domain-certificate match |

## Requirements
1. **HTTPS Enforcement**: All pages must be served over HTTPS
2. **CSP Compatibility**: Existing CSP headers will be extended
3. **Modern Browsers**: Supports Chrome/Firefox/Edge (IE unsupported)

## Implementation Notes
1. **Input Sanitization**:
   - Runs on every keystroke in text fields
   - Blocks dangerous characters with option to unblock
   - Example to allowlist: `<textarea data-sanitization="disabled"></textarea>`

2. **CSP Management**:
   - Blocks non-CSP fetches at runtime

3. **Certificate Checks**:
   - Validates SSL certificates match requested domains
   - Terminates mismatched connections

## Performance Impact
- Minimal runtime overhead (< 2ms initialization)
- Zero ongoing CPU usage during idle
- Network latency only during certificate validation

> **Critical Note**: This script supplements but doesn't replace server-side security. Always implement backend validation and proper HTTP headers.

## Contribute
Send me a pull request!

## See our terms & conditions
[Our terms & conditions](https://cydogbrowser.com/cyterms.html)

## Want to know more?
Visit [https://cydogbrowser.com](https://cydogbrowser.com/)
