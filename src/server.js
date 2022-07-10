import fetch from 'node-fetch'
import jwonwebtoken from 'jsonwebtoken'
import jwkToPem from 'jwk-to-pem'
import express from 'express'

const { verify, decode } = jwonwebtoken

// e.g https://[tenant-domain]/.well-known/jwks.json
const ISSUER_ENDPOINT = process.env.ISSUER_ENDPOINT

const newJWKsClient = issuerUrl => {
  const ErrJWKNotFound = new Error('jwk not found')
  const ErrKidNotFound = new Error('kid not found')
  const ErrUnauthorized = new Error('unauthorized')

  const getJWKs = async () => {
    try {
      // worth implementing some cache over there
      const res = await fetch(issuerUrl)
      const { keys: jwks } = await res.json()
      return [undefined, jwks]
    } catch (e) {
      return [e]
    }
  }

  const getJWK = async kid => {
    const [getJWKsError, jwks] = await getJWKs()
    if (getJWKsError) {
      return [getJWKsError]
    }

    const jwk = jwks.find(jwk => kid === jwk.kid)
    if (!jwk) {
      return [ErrJWKNotFound]
    }

    return [undefined, jwk]
  }

  const verifyToken = async token => {
    try {
      const {
        header,
        payload: { iss: issuer },
      } = decode(token, { complete: true })
      const { kid } = header

      if (!kid) {
        return [ErrKidNotFound]
      }

      const [getJWKError, jwk] = await getJWK(kid)
      if (getJWKError) {
        return [getJWKError]
      }

      const pem = jwkToPem(jwk)
      const userPayload = await verify(token, pem, {
        issuer,
        complete: true,
      })

      return [undefined, userPayload]
    } catch (e) {
      return [e]
    }
  }

  const authorizationMiddleware = async (req, res, next) => {
    const { authorization } = req.headers
    if (!authorization) {
      return res.status(401).end(ErrUnauthorized.message)
    }

    if (!/Bearer /.test(authorization)) {
      return res.status(401).end(ErrUnauthorized.message)
    }

    const token = authorization.replace('Bearer ', '')
    const [verifyTokenError] = await verifyToken(token)
    if (verifyTokenError) {
      return res.status(401).end(verifyTokenError.message)
    }

    next()
  }

  return {
    verifyToken,
    getJWK,
    getJWKs,
    authorizationMiddleware,
  }
}

const { authorizationMiddleware } = newJWKsClient(ISSUER_ENDPOINT)
const PORT = process.env.PORT || 3000
const app = express()

// Uncomment in case you want to run authentication in all routes
// app.use(authorizationMiddleware)

app.get('/public', (req, res) => {
  return res.end('public')
})
app.get('/private', authorizationMiddleware, (req, res) => {
  return res.end('private')
})

app.listen(PORT, () =>
  console.log(`The server is listening on port http://localhost:${PORT}`)
)
