-- | Validation of AAD-issued tokens against the tenant's published
-- signing keys (JWKS). Consumed by both login flows: the Teams
-- exchange validates the token from @getAuthToken@, the browser flow
-- validates the id_token from the code exchange. Both carry the same
-- claim vocabulary; 'entraIdentity' is the shared extraction.
--
-- Microsoft rotates signing keys unannounced, hence the cache
-- discipline: keys are fetched lazily (the service must start while
-- AAD is unreachable), cached for 24 h, served stale when a refetch
-- fails, and force-refreshed at most once a minute when a token
-- references an unknown key id.
module Marmay.Auth.Microsoft.AuthTokenValidator
  ( JWKSCache
  , mkJWKSCache
  , mkJWKSCacheWith
  , getJWKS
  , validateEntraToken
  , EntraClaims (..)
  , EntraIdentity (..)
  , entraIdentity
  ) where

import Control.Applicative ((<|>))
import Control.Concurrent.STM (TVar, atomically, modifyTVar', newTVarIO, readTVarIO)
import Control.Exception (try)
import Control.Lens.Operators
import Crypto.JOSE qualified as JOSE
import Crypto.JOSE.JWA.JWS qualified as JWA
import Crypto.JWT qualified as JOSE
import Data.Aeson (FromJSON (..), Value (Object), withObject, (.:), (.:?))
import Data.Aeson qualified as A
import Data.Bifunctor (first)
import Data.ByteString.Lazy (ByteString)
import Data.Maybe (fromMaybe, maybeToList)
import Data.Set qualified as Set
import Data.String (fromString)
import Data.Text (Text)
import Data.Text qualified as T
import Data.Time (UTCTime, diffUTCTime, getCurrentTime)
import Marmay.Auth.OAuth2Config (OAuth2Config (..))
import Marmay.Auth.SecurityConfig (SecurityConfig (..), TeamsConfig (..))
import Network.HTTP.Client qualified as H
import Network.HTTP.Types.Status (statusCode, statusIsSuccessful)
import System.IO (hPutStrLn, stderr)

data JWKSState = JWKSState
  { keySet :: !(Maybe (JOSE.JWKSet, UTCTime))
    -- ^ Last successfully fetched key set and its fetch time.
  , lastAttempt :: !(Maybe UTCTime)
    -- ^ Last fetch attempt (successful or not); rate-limits forced
    --   refetches so garbage @kid@s cannot spam Microsoft.
  }

data JWKSCache = JWKSCache
  { fetch :: !(IO (Either Text JOSE.JWKSet))
  , state :: !(TVar JWKSState)
  }

cacheDuration :: Double
cacheDuration = 24 * 3600

minRefetchInterval :: Double
minRefetchInterval = 60

-- | Cache backed by the tenant's discovery endpoint. No fetch happens
-- until the first validation.
mkJWKSCache :: H.Manager -> Text -> IO JWKSCache
mkJWKSCache manager tenantId = mkJWKSCacheWith fetchKeys
  where
    url =
      "https://login.microsoftonline.com/"
        <> T.unpack tenantId
        <> "/discovery/v2.0/keys"
    fetchKeys = do
      result <- try @H.HttpException $ do
        request <- H.parseRequest url
        H.httpLbs request manager
      pure $ case result of
        Left e -> Left $ "JWKS fetch failed: " <> T.pack (show e)
        Right response
          | not (statusIsSuccessful (H.responseStatus response)) ->
              Left $
                "JWKS endpoint returned status "
                  <> T.pack (show (statusCode (H.responseStatus response)))
          | otherwise ->
              first (("Failed to parse JWKS document: " <>) . T.pack) $
                A.eitherDecode (H.responseBody response)

-- | Cache with an injected fetch action (tests).
mkJWKSCacheWith :: IO (Either Text JOSE.JWKSet) -> IO JWKSCache
mkJWKSCacheWith fetchKeys = do
  state <- newTVarIO JWKSState{keySet = Nothing, lastAttempt = Nothing}
  pure JWKSCache{fetch = fetchKeys, state = state}

-- | Cached keys if fresh, otherwise refetch; on refetch failure serve
-- stale keys (an AAD outage must not break logins that cached keys
-- can still validate).
getJWKS :: JWKSCache -> IO (Either Text JOSE.JWKSet)
getJWKS cache = do
  now <- getCurrentTime
  st <- readTVarIO cache.state
  case st.keySet of
    Just (keys, fetchedAt)
      | realToFrac (diffUTCTime now fetchedAt) < cacheDuration ->
          pure $ Right keys
    _ -> fetchAndStore cache now

-- | Refetch for the unknown-@kid@ path (key rotation), suppressed
-- when the last attempt is younger than 'minRefetchInterval'.
forceRefreshJWKS :: JWKSCache -> IO (Either Text JOSE.JWKSet)
forceRefreshJWKS cache = do
  now <- getCurrentTime
  st <- readTVarIO cache.state
  let tooSoon = maybe False (\t -> realToFrac (diffUTCTime now t) < minRefetchInterval) st.lastAttempt
  if tooSoon
    then pure $ maybe (Left "JWKS refetch suppressed (rate limit)") (Right . fst) st.keySet
    else fetchAndStore cache now

fetchAndStore :: JWKSCache -> UTCTime -> IO (Either Text JOSE.JWKSet)
fetchAndStore cache now = do
  atomically $ modifyTVar' cache.state $ \s -> s{lastAttempt = Just now}
  result <- cache.fetch
  case result of
    Right keys -> do
      atomically $ modifyTVar' cache.state $ \s -> s{keySet = Just (keys, now)}
      pure $ Right keys
    Left err -> do
      st <- readTVarIO cache.state
      case st.keySet of
        Just (staleKeys, _) -> do
          hPutStrLn stderr $
            "marmay-auth: JWKS refetch failed, serving stale keys: " <> T.unpack err
          pure $ Right staleKeys
        Nothing -> pure $ Left err

-- | Claims of an AAD-issued v2.0 token. @oid@ is the immutable
-- directory object id and the identity key; the username claims are
-- optional in v2 tokens (usually only @preferred_username@ arrives).
-- @given_name@ / @family_name@ are Entra *optional claims*: they arrive
-- only once the app registration's token configuration adds them (for
-- the ID token -- browser flow -- and the access token -- Teams SSO).
data EntraClaims = EntraClaims
  { jwtClaims :: !JOSE.ClaimsSet
  , oid :: !Text
  , preferredUsername :: !(Maybe Text)
  , upn :: !(Maybe Text)
  , email :: !(Maybe Text)
  , name :: !(Maybe Text)
  , givenName :: !(Maybe Text)
  , familyName :: !(Maybe Text)
  }
  deriving (Eq, Show)

instance JOSE.HasClaimsSet EntraClaims where
  claimsSet f s = fmap (\cs -> s{jwtClaims = cs}) (JOSE.claimsSet f s.jwtClaims)

instance FromJSON EntraClaims where
  parseJSON = withObject "EntraClaims" $ \o ->
    EntraClaims
      <$> parseJSON (Object o)
      <*> o .: "oid"
      <*> o .:? "preferred_username"
      <*> o .:? "upn"
      <*> o .:? "email"
      <*> o .:? "name"
      <*> o .:? "given_name"
      <*> o .:? "family_name"

-- | The identity both login flows feed into assertion minting.
data EntraIdentity = EntraIdentity
  { oid :: !Text
  , upn :: !Text
  , name :: !Text
  }
  deriving (Eq, Show)

-- | Shared identity extraction: @preferred_username ?? upn ?? email@,
-- lowercased. The display name is @given_name family_name@ when both
-- arrive (the tenant's own @name@ is "Nachname Vorname", which reads
-- wrong wherever the name is published), else @name@, else the upn.
entraIdentity :: EntraClaims -> Either Text EntraIdentity
entraIdentity claims =
  case claims.preferredUsername <|> claims.upn <|> claims.email of
    Nothing -> Left "Token carries no username claim (preferred_username/upn/email)"
    Just username ->
      let lowered = T.toLower username
      in Right
          EntraIdentity
            { oid = claims.oid
            , upn = lowered
            , name = fromMaybe lowered (fullName <|> claims.name)
            }
  where
    -- Both parts present and non-blank; a lone or blank part falls through
    -- to the name claim rather than yielding a half name.
    fullName = do
      g <- nonBlank =<< claims.givenName
      f <- nonBlank =<< claims.familyName
      pure (g <> " " <> f)
    nonBlank t = let s = T.strip t in if T.null s then Nothing else Just s

-- | Validate a compact-encoded AAD token: RS256 against the tenant
-- JWKS (key selected by @kid@), byte-exact tenant issuer, audience in
-- the accepted set, 300 s skew. On a signature/key failure, one
-- forced key refetch and retry covers Microsoft's key rotation.
validateEntraToken :: JWKSCache -> SecurityConfig -> ByteString -> IO (Either Text EntraClaims)
validateEntraToken cache securityConfig raw = do
  keysResult <- getJWKS cache
  case keysResult of
    Left err -> pure $ Left $ "JWKS unavailable: " <> err
    Right keys -> do
      firstTry <- verifyWith keys
      case firstTry of
        Left err | isKeyFailure err -> do
          refreshed <- forceRefreshJWKS cache
          case refreshed of
            Left _ -> pure $ Left $ renderError err
            Right freshKeys -> first renderError <$> verifyWith freshKeys
        other -> pure $ first renderError other
  where
    expectedIssuer =
      "https://login.microsoftonline.com/"
        <> securityConfig.oauth2Config.tenantId
        <> "/v2.0"
    acceptedAudiences =
      map (fromString . T.unpack) $
        securityConfig.oauth2Config.clientId
          : maybeToList securityConfig.teamsConfig.applicationIdUri
    validationSettings =
      JOSE.defaultJWTValidationSettings (`elem` acceptedAudiences)
        & JOSE.jwtValidationSettingsIssuerPredicate .~ (== fromString (T.unpack expectedIssuer))
        & JOSE.jwtValidationSettingsAllowedSkew .~ 300
        & JOSE.validationSettingsAlgorithms .~ Set.singleton JWA.RS256
    verifyWith :: JOSE.JWKSet -> IO (Either JOSE.JWTError EntraClaims)
    verifyWith keys = JOSE.runJOSE $ do
      token :: JOSE.SignedJWT <- JOSE.decodeCompact raw
      JOSE.verifyJWT validationSettings keys token
    isKeyFailure = \case
      JOSE.JWSError _ -> True
      _ -> False
    renderError :: JOSE.JWTError -> Text
    renderError = T.pack . show
