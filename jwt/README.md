# JWT
The JWT package provides functions to parse a JWT token and extract entity data from it.

### Usage
#### Create a new instance of a JWT parser

```go
  import (
    "github.com/ONSdigital/dp-authorisation/v2/jwt"
    "github.com/ONSdigital/dp-authorisation/v2/permissions"
  )
  
  ...

  p, err := jwt.NewCognitoRSAParser(publicKey)
  ```
The public key value should come from the service configuration. The `NewCognitoRSAParser` is tailored
for JWT tokens generated by AWS Cognito. These tokens use RSA encryption for token verification, and have
Cognito specific claims. Other Parser implementations can be used, as long as they implement the generic parse function.

```
Parse(tokenString string) (*permsdk.EntityData, error)
```

#### Parse a JWT token

```go
entityData, err := p.Parse(jwtToken)
```
