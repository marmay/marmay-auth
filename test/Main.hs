-- | Protocol tests. The ReplayProtection cases exist because the
-- prune predicate's failure mode is invisible in manual testing: an
-- inverted comparison once shipped inside a fully working login flow
-- (every single login succeeds; only replays behave wrong). The
-- Teams-flow tests run the real validator and exchange handler
-- against self-signed AAD-shaped tokens (JWKS injected, no network).
module Main (main) where

import Control.Lens ((&), (?~), (^.))
import Crypto.JOSE qualified as JOSE
import Crypto.JOSE.JWA.JWS qualified as JWA
import Crypto.JOSE.JWK (KeyMaterialGenParam (OKPGenParam, RSAGenParam), OKPCrv (Ed25519), asPublicKey, genJWK, jwkKid)
import Crypto.JWT qualified as JWT
import Data.Aeson ((.=))
import Data.Aeson qualified as A
import Data.Aeson.Key qualified as AKey
import Data.Aeson.KeyMap qualified as KM
import Data.ByteString.Lazy qualified as BL
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Text.Encoding qualified as TE
import Data.Time (addUTCTime, getCurrentTime)
import Data.Time.Clock.POSIX (utcTimeToPOSIXSeconds)
import Data.UUID (UUID)
import Data.UUID qualified as UUID
import Marmay.Auth.Assertion
  ( IdentityAssertion (..)
  , generateIdentityAssertion'
  , validateIdentityAssertion'
  )
import Marmay.Auth.HTTP
  ( AuthEnv (..)
  , ExchangeResponse (..)
  , isAllowedReturnUrl
  , mintedAudience
  , securityHeaders
  , teamsExchangeHandler
  )
import Marmay.Auth.Microsoft.AuthTokenValidator
  ( EntraIdentity (..)
  , JWKSCache
  , entraIdentity
  , mkJWKSCacheWith
  , validateEntraToken
  )
import Marmay.Auth.OAuth2Config (OAuth2Config (..))
import Marmay.Auth.ReplayProtection (ensureUnconsumed, mkConsumedLog)
import Marmay.Auth.SecurityConfig (SecurityConfig (..), TeamsConfig (..))
import Network.HTTP.Client (defaultManagerSettings, newManager)
import Network.HTTP.Types (status200)
import Network.URI (parseAbsoluteURI, uriToString)
import Network.Wai qualified as Wai
import Network.Wai.Internal (ResponseReceived (..))
import Servant (runHandler)
import Servant.Server (ServerError (..))
import System.Exit (exitFailure)

main :: IO ()
main = do
  failures <- newIORef (0 :: Int)
  let check name cond = do
        if cond
          then putStrLn ("ok:   " <> name)
          else do
            putStrLn ("FAIL: " <> name)
            modifyIORef' failures (+ 1)

  replayProtectionTests check
  assertionTests check
  jwksDocumentTests check
  entraValidationTests check
  returnUrlTests check
  audienceDerivationTests check
  exchangeHandlerTests check
  securityHeaderTests check

  n <- readIORef failures
  if n == 0
    then putStrLn "all tests passed"
    else do
      putStrLn (show n <> " test(s) failed")
      exitFailure

uuid1, uuid2 :: UUID
uuid1 = UUID.fromWords 1 2 3 4
uuid2 = UUID.fromWords 5 6 7 8

replayProtectionTests :: (String -> Bool -> IO ()) -> IO ()
replayProtectionTests check = do
  now <- getCurrentTime
  let future = addUTCTime 120 now
      past = addUTCTime (-1) now

  consumedLog <- mkConsumedLog
  r1 <- ensureUnconsumed uuid1 future consumedLog
  check "fresh assertion id is unconsumed" r1
  r2 <- ensureUnconsumed uuid1 future consumedLog
  check "repeated assertion id is rejected" (not r2)

  -- Pruning: an entry past its validity must be forgotten, so the
  -- same id passes again. (With the historical inverted predicate,
  -- it was the LIVE entries that were forgotten instead.)
  expiredLog <- mkConsumedLog
  r3 <- ensureUnconsumed uuid2 past expiredLog
  check "id with already-past validity is accepted" r3
  r4 <- ensureUnconsumed uuid2 future expiredLog
  check "expired entry is pruned, id usable again" r4
  r5 <- ensureUnconsumed uuid2 future expiredLog
  check "after re-consumption the id is rejected again" (not r5)

assertionTests :: (String -> Bool -> IO ()) -> IO ()
assertionTests check = do
  signingKey <- genJWK (OKPGenParam Ed25519)
  let publicKey = fromJust (signingKey ^. asPublicKey)
      audience = fromJust (parseAbsoluteURI "https://9a.example.com")
      otherAudience = fromJust (parseAbsoluteURI "https://9b.example.com")
      assertion =
        IdentityAssertion
          { assertionId = uuid1
          , oid = "240fec71-0000-4000-8000-000000000001"
          , upn = "erika@example.com"
          , name = "Erika Musterfrau"
          }

  generated <- generateIdentityAssertion' signingKey 60 audience assertion
  case generated of
    Left err -> check ("assertion generation succeeds: " <> show err) False
    Right token -> do
      -- The consumer scenario: validation with only the public key.
      validated <- validateIdentityAssertion' publicKey 10 audience token
      case validated of
        Left err -> check ("validation with public key succeeds: " <> show err) False
        Right (roundTripped, _validUntil) ->
          check "assertion round-trips through sign/verify" (roundTripped == assertion)

      wrongAudience <- validateIdentityAssertion' publicKey 10 otherAudience token
      check "validation rejects the wrong audience" (either (const True) (const False) wrongAudience)

-- Shared fixtures for the Teams-flow tests --------------------------

testTenant, testClientId, testAppIdUri, testOid :: Text
testTenant = "8231a750-0000-4000-8000-000000000000"
testClientId = "9bbc5abe-0000-4000-8000-000000000000"
testAppIdUri = "api://example.com/" <> testClientId
testOid = "240fec71-0000-4000-8000-000000000042"

testIssuer :: Text
testIssuer = "https://login.microsoftonline.com/" <> testTenant <> "/v2.0"

mkTestSecurityConfig :: JOSE.JWK -> SecurityConfig
mkTestSecurityConfig issuerJwk =
  SecurityConfig
    { oauth2Config =
        OAuth2Config
          { clientId = testClientId
          , clientSecret = ""
          , redirectUri = "https://auth.example.com/auth/callback"
          , tenantId = testTenant
          }
    , authIssuerJwk = issuerJwk
    , allowedReturnDomain = "example.com"
    , tokenExpiryDuration = 60
    , teamsConfig =
        TeamsConfig
          { applicationIdUri = Just testAppIdUri
          , frameAncestors = ["teams.microsoft.com"]
          }
    , laxReturnUrlCheck = False
    }

-- | Sign an aeson object as a compact JWS with the given algorithm,
-- carrying the test key id so JWKSet key selection works like AAD's.
signToken :: JOSE.JWK -> JWA.Alg -> A.Value -> IO BL.ByteString
signToken key alg payload = do
  result <- JOSE.runJOSE @JWT.JWTError $ do
    jwt <-
      JWT.signJWT
        key
        (JOSE.newJWSHeader (JOSE.RequiredProtection, alg) & JOSE.kid ?~ JOSE.HeaderParam JOSE.RequiredProtection "test-key")
        payload
    pure (JOSE.encodeCompact jwt)
  either (fail . show) pure result

-- | The claim shape the gate test observed in real v2 tokens; the
-- username deliberately mixed-case to pin the lowercasing.
aadClaims :: Integer -> [(String, A.Value)]
aadClaims expSecs =
  [ ("aud", A.String testClientId)
  , ("iss", A.String testIssuer)
  , ("exp", A.Number (fromInteger expSecs))
  , ("oid", A.String testOid)
  , ("preferred_username", A.String "Erika.Musterfrau@Example.COM")
  , ("name", A.String "Erika Musterfrau")
  ]

claimsObject :: [(String, A.Value)] -> A.Value
claimsObject kvs = A.object [AKey.fromString k .= v | (k, v) <- kvs]

override :: String -> A.Value -> [(String, A.Value)] -> [(String, A.Value)]
override k v kvs = (k, v) : filter ((/= k) . fst) kvs

remove :: String -> [(String, A.Value)] -> [(String, A.Value)]
remove k = filter ((/= k) . fst)

-- | An RSA signing key plus a validator cache injected with its
-- public half (as AAD's discovery endpoint would serve it).
mkSigningRig :: IO (JOSE.JWK, SecurityConfig, JWKSCache)
mkSigningRig = do
  rsaKey <- (jwkKid ?~ "test-key") <$> genJWK (RSAGenParam 256)
  issuerJwk <- genJWK (OKPGenParam Ed25519)
  let publicSet = JOSE.JWKSet [fromJust (rsaKey ^. asPublicKey)]
  cache <- mkJWKSCacheWith (pure (Right publicSet))
  pure (rsaKey, mkTestSecurityConfig issuerJwk, cache)

-- Teams-flow tests --------------------------------------------------

jwksDocumentTests :: (String -> Bool -> IO ()) -> IO ()
jwksDocumentTests check = do
  rsaKey <- genJWK (RSAGenParam 256)
  let publicJwk = A.toJSON (fromJust (rsaKey ^. asPublicKey))
      -- The shape of AAD's discovery document: keys carry extra
      -- Microsoft-specific properties the parser must tolerate.
      augmented = case publicJwk of
        A.Object o ->
          A.Object $
            KM.insert "kid" (A.String "abc123") $
              KM.insert "cloud_instance_name" (A.String "microsoftonline.com") o
        v -> v
      doc = A.encode (A.object ["keys" .= [augmented]])
  case A.eitherDecode @JOSE.JWKSet doc of
    Left err -> check ("JWKS discovery document parses: " <> err) False
    Right (JOSE.JWKSet keys) ->
      check "JWKS discovery document parses to a non-empty key set" (not (null keys))

entraValidationTests :: (String -> Bool -> IO ()) -> IO ()
entraValidationTests check = do
  (rsaKey, securityConfig, cache) <- mkSigningRig
  now <- getCurrentTime
  let nowSecs = floor (utcTimeToPOSIXSeconds now) :: Integer
      freshExp = nowSecs + 600
      validate claims = do
        token <- signToken rsaKey JWA.RS256 (claimsObject claims)
        validateEntraToken cache securityConfig token
      rejects name claims = validate claims >>= check name . either (const True) (const False)

  accepted <- validate (aadClaims freshExp)
  case accepted of
    Left err -> check ("valid AAD token is accepted: " <> T.unpack err) False
    Right claims -> do
      check "valid AAD token is accepted" True
      case entraIdentity claims of
        Left err -> check ("identity extraction succeeds: " <> T.unpack err) False
        Right identity -> do
          check "identity oid comes from the oid claim" (identity.oid == testOid)
          check "identity upn is the lowercased preferred_username" (identity.upn == "erika.musterfrau@example.com")
          check "identity name comes from the name claim" (identity.name == "Erika Musterfrau")

  -- The optional claims, once the app registration sends them, take
  -- precedence over the tenant's "Nachname Vorname" display name.
  let identityName claims = either (const Nothing) (Just . (.name)) . entraIdentity =<< either (const Nothing) Just claims
      withParts g f = override "name" (A.String "Musterfrau Erika") . override "given_name" (A.String g) . override "family_name" (A.String f)
  fullName <- validate (withParts "Erika" "Musterfrau" (aadClaims freshExp))
  check "given_name + family_name form the display name" (identityName fullName == Just "Erika Musterfrau")
  onlyGiven <- validate (remove "family_name" (withParts "Erika" "Musterfrau" (aadClaims freshExp)))
  check "a lone given_name falls back to the name claim" (identityName onlyGiven == Just "Musterfrau Erika")
  blankFamily <- validate (withParts "Erika" "  " (aadClaims freshExp))
  check "a blank family_name falls back to the name claim" (identityName blankFamily == Just "Musterfrau Erika")
  paddedParts <- validate (withParts " Erika " " Musterfrau " (aadClaims freshExp))
  check "name parts are trimmed" (identityName paddedParts == Just "Erika Musterfrau")

  appIdUriAudience <- validate (override "aud" (A.String testAppIdUri) (aadClaims freshExp))
  check "application-id-uri audience is also accepted" (either (const False) (const True) appIdUriAudience)

  rejects "wrong issuer is rejected" (override "iss" "https://login.microsoftonline.com/other-tenant/v2.0" (aadClaims freshExp))
  rejects "wrong audience is rejected" (override "aud" "https://graph.microsoft.com" (aadClaims freshExp))
  rejects "expired token is rejected (beyond skew)" (aadClaims (nowSecs - 400))
  rejects "missing oid is rejected" (remove "oid" (aadClaims freshExp))

  ps256 <- signToken rsaKey JWA.PS256 (claimsObject (aadClaims freshExp))
  ps256Result <- validateEntraToken cache securityConfig ps256
  check "non-RS256 algorithm is rejected" (either (const True) (const False) ps256Result)

  noUsername <- validate (remove "preferred_username" (aadClaims freshExp))
  case noUsername of
    Left err -> check ("claims without username still validate: " <> T.unpack err) False
    Right claims ->
      check
        "identity extraction fails without any username claim"
        (either (const True) (const False) (entraIdentity claims))

returnUrlTests :: (String -> Bool -> IO ()) -> IO ()
returnUrlTests check = do
  let allowed url = maybe False (isAllowedReturnUrl False "example.com") (parseAbsoluteURI url)
  check "subdomain https URL is allowed" (allowed "https://9a.example.com/app/grid")
  check "apex https URL is allowed" (allowed "https://example.com/")
  check "foreign domain is rejected" (not (allowed "https://evil.com/"))
  check "suffix trick without dot is rejected" (not (allowed "https://evilexample.com/"))
  check "userinfo is rejected" (not (allowed "https://user@9a.example.com/"))
  check "explicit port is rejected" (not (allowed "https://9a.example.com:8443/"))
  check "plain http is rejected" (not (allowed "http://9a.example.com/"))
  check "fragment is rejected" (not (allowed "https://9a.example.com/app#x"))

audienceDerivationTests :: (String -> Bool -> IO ()) -> IO ()
audienceDerivationTests check = do
  let derive url = (\u -> uriToString id (mintedAudience u) "") <$> parseAbsoluteURI url
  check
    "audience is the bare origin of the return URL"
    (derive "https://9a.example.com/app/assignments?tab=1" == Just "https://9a.example.com")
  check
    "audience of a bare origin is itself"
    (derive "https://9a.example.com" == Just "https://9a.example.com")

exchangeHandlerTests :: (String -> Bool -> IO ()) -> IO ()
exchangeHandlerTests check = do
  (rsaKey, securityConfig, cache) <- mkSigningRig
  manager <- newManager defaultManagerSettings
  let env = AuthEnv{manager = manager, securityConfig = securityConfig, jwksCache = cache, applications = []}
  now <- getCurrentTime
  let freshExp = floor (utcTimeToPOSIXSeconds now) + 600 :: Integer
  token <- signToken rsaKey JWA.RS256 (claimsObject (aadClaims freshExp))

  let run mReturn body = runHandler (teamsExchangeHandler env mReturn body)
      failsWith name code result = check name (either ((== code) . errHTTPCode) (const False) result)

  happy <- run (Just "https://9a.example.com/app/assignments") token
  case happy of
    Left err -> check ("exchange succeeds for a valid token: " <> show err.errHTTPCode) False
    Right response -> do
      let minted = BL.fromStrict (TE.encodeUtf8 response.assertion)
          publicIssuer = fromJust (securityConfig.authIssuerJwk ^. asPublicKey)
          audience = fromJust (parseAbsoluteURI "https://9a.example.com")
          sibling = fromJust (parseAbsoluteURI "https://9b.example.com")
      validated <- validateIdentityAssertion' publicIssuer 10 audience minted
      case validated of
        Left err -> check ("exchange output validates for the return origin: " <> show err) False
        Right (identityAssertion, _) -> do
          check "exchange output validates for the return origin" True
          check "assertion carries the oid" (identityAssertion.oid == testOid)
          check "assertion carries the lowercased upn" (identityAssertion.upn == "erika.musterfrau@example.com")
      wrongOrigin <- validateIdentityAssertion' publicIssuer 10 sibling minted
      check "exchange output fails for a sibling origin" (either (const True) (const False) wrongOrigin)

  run Nothing token >>= failsWith "missing return URL yields 400" 400
  run (Just "not a url") token >>= failsWith "unparseable return URL yields 400" 400
  run (Just "https://evil.com/app") token >>= failsWith "off-domain return URL yields 403" 403
  run (Just "https://9a.example.com/app") "garbage" >>= failsWith "garbage token yields 401" 401

securityHeaderTests :: (String -> Bool -> IO ()) -> IO ()
securityHeaderTests check = do
  issuerJwk <- genJWK (OKPGenParam Ed25519)
  let securityConfig = mkTestSecurityConfig issuerJwk
      probe path = do
        captured <- newIORef []
        let app _ respond = respond (Wai.responseLBS status200 [] "")
            request = Wai.defaultRequest{Wai.pathInfo = path}
        _ <-
          securityHeaders securityConfig app request $ \response -> do
            writeIORef captured (Wai.responseHeaders response)
            pure ResponseReceived
        readIORef captured

  authHeaders <- probe ["auth", "login"]
  check "/auth/* is never framed" (lookup "Content-Security-Policy" authHeaders == Just "frame-ancestors 'none'")
  check "/auth/* is never cached" (lookup "Cache-Control" authHeaders == Just "no-store")

  ssoHeaders <- probe ["teams", "sso"]
  check "/teams/sso carries the Teams allowlist" (lookup "Content-Security-Policy" ssoHeaders == Just "frame-ancestors teams.microsoft.com")
  check "/teams/sso is never cached" (lookup "Cache-Control" ssoHeaders == Just "no-store")

  configHeaders <- probe ["teams", "config"]
  check "/teams/* carries the Teams allowlist" (lookup "Content-Security-Policy" configHeaders == Just "frame-ancestors teams.microsoft.com")
  check "/teams/* is cacheable" (lookup "Cache-Control" configHeaders == Nothing)

  otherHeaders <- probe ["somewhere", "else"]
  check "unknown paths are never framed" (lookup "Content-Security-Policy" otherHeaders == Just "frame-ancestors 'none'")
