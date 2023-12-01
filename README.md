# totp-cli

This is a bare-bones CLI that derives the 6 digit MFA code associated with a MFA's text secret.  The codes rotate every 30 seconds.  

Based the work on RFC 4226 - <https://www.ietf.org/rfc/rfc4226.txt>

## How to build it

Clone the repo and type `make`.

## How to run it

From a command line, type: 

```totp THETEXTSECRET```

Two values are returned, the 6 digit code and the number of seconds remaining until the code regenerates.



