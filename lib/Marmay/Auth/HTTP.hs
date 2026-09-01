module Marmay.Auth.HTTP
  ( authServer
  , authAPI
  , AuthEnv (..)
  ) where

import Servant (Get, Post, JSON, OctetStream, ReqBody, (:<|>) (..), (:>), QueryParam, Header, Server, Handler, throwError, ServerError (..), err302, err400, err401, err403, err500)
import Data.Text (Text)
import Marmay.Auth.SecurityConfig (SecurityConfig(..))
import Control.Monad (unless)
import qualified Data.UUID.V4 as UUID
import Control.Monad.IO.Class (MonadIO(..))
import qualified Data.UUID as UUID
import Data.Aeson ((.=))
import qualified Data.Aeson as A
import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import Network.HTTP.Types (urlEncode, urlDecode)
import Data.Text.Encoding (encodeUtf8, decodeUtf8)
import qualified Data.Text.Lazy as TL
import qualified Data.Text.Lazy.Encoding as TLE
import Marmay.Auth.OAuth2Config (OAuth2Config(..))
import Servant.HTML.Blaze (HTML)
import Text.Blaze.Html (Html)
import Network.URI (parseAbsoluteURI, URI (..), URIAuth (..), uriToString)
import qualified Data.Text as T
import Web.Cookie (parseCookies, Cookies)
import GHC.Generics (Generic)
import Marmay.Auth.Microsoft.CodeExchange (exchangeCodeForIdToken)
import Marmay.Auth.Microsoft.AuthTokenValidator (JWKSCache, validateEntraToken, entraIdentity, EntraIdentity(..))
import Network.HTTP.Client (Manager)
import Marmay.Auth.Assertion (IdentityAssertion(..), generateIdentityAssertion')
import Data.Proxy (Proxy(..))

-- Browser flow (login/callback) and Teams flow (teams/exchange) live
-- side by side here; both converge on the shared back half below
-- (mkIdentityAssertion, mintedAudience, isAllowedReturnUrl). Split
-- Teams routes into their own module only once the shared helpers get
-- a home of their own.
type AuthAPI =
  "auth" :>
  ( "login"
         :> QueryParam "return" Text
         :> Get '[HTML] Html
  :<|> "callback"
         :> QueryParam "code" Text
         :> QueryParam "state" Text
         :> Header "Cookie" Text
         :> Get '[HTML] Html
  :<|> "teams" :> "exchange"
         :> QueryParam "return" Text
         :> ReqBody '[OctetStream] BL.ByteString
         :> Post '[JSON] ExchangeResponse
  )

authAPI :: Proxy AuthAPI
authAPI = Proxy

-- | Everything the handlers need; bundled because threading three
-- separate parameters through every handler stopped scaling.
data AuthEnv = AuthEnv
  { manager :: !Manager
  , securityConfig :: !SecurityConfig
  , jwksCache :: !JWKSCache
  }

authServer :: AuthEnv -> Server AuthAPI
authServer env = (loginHandler env.securityConfig) :<|> (callbackHandler env) :<|> (teamsExchangeHandler env)

loginHandler :: SecurityConfig -> Maybe Text -> Handler Html
loginHandler securityConfig returnUrl = do
  returnUrl' <- maybe handleMissingReturnUrl pure returnUrl
                >>= pure . parseAbsoluteURI . T.unpack
                >>= maybe handleReturnUrlInvalid pure
  unless (isAllowedReturnUrl securityConfig.laxReturnUrlCheck securityConfig.allowedReturnDomain returnUrl') $
    handleDisallowedReturnUrl
  csrfState <- liftIO UUID.nextRandom
  let
    locationHeader = ("Location", getAuthorizationUrlWithState securityConfig.oauth2Config (UUID.toText csrfState))
    csrfStateCookie = mkCookie "csrfState" (UUID.toText csrfState)
    returnUrlCookie = mkCookie "returnUrl" (T.pack (uriToString id returnUrl' ""))

  throwError err302
               { errHeaders = [ locationHeader, csrfStateCookie, returnUrlCookie ] }

  where
    handleMissingReturnUrl =
      throwError err400 {errBody = "Missing return URL"}
    handleReturnUrlInvalid =
      throwError err400 {errBody = "Invalid return URL"}
    handleDisallowedReturnUrl =
      throwError err400 {errBody = "Disallowed return URL"}
    mkCookie name value =
      ("Set-Cookie", B.concat [name, "=", urlEncode False (encodeUtf8 value), "; HttpOnly; Secure; SameSite=Lax; Path=/auth/callback; Max-Age=600"])

callbackHandler :: AuthEnv -> Maybe Text -> Maybe Text -> Maybe Text -> Handler Html
callbackHandler env code state cookies = do
  let securityConfig = env.securityConfig
  code' <- maybe handleMissingCode pure code
  state' <- maybe handleMissingState pure state
  (csrfState, returnUrl) <- maybe handleMissingCookies pure cookies
                              >>= parseAllCookies
  returnUrl' <- maybe (handleInvalidReturnUrl returnUrl) pure
                  $ parseAbsoluteURI $ T.unpack $ returnUrl
  unless (csrfState == state') $
    handleNonMatchingCsrfState state' csrfState
  unless (isAllowedReturnUrl securityConfig.laxReturnUrlCheck securityConfig.allowedReturnDomain returnUrl') $
    handleDisallowedReturnUrl
  idToken <- liftIO (exchangeCodeForIdToken env.manager securityConfig.oauth2Config code')
             >>= either handleTokenExchangeError pure
  claims <- liftIO (validateEntraToken env.jwksCache securityConfig (B.fromStrict (encodeUtf8 idToken)))
             >>= either handleIdTokenError pure
  identity <- either handleIdTokenError pure (entraIdentity claims)
  identityAssertion <- liftIO (mkIdentityAssertion identity)
  mintedToken <- liftIO (generateIdentityAssertion' securityConfig.authIssuerJwk securityConfig.tokenExpiryDuration (mintedAudience returnUrl') identityAssertion)
    >>= either handleMintingError pure
  throwError err302 {
    errHeaders = [ ("Location", B.concat [ encodeUtf8 returnUrl
                                         , "#itoken="
                                         , B.toStrict mintedToken
                                         ])
                 , clearCookie "csrfState"
                 , clearCookie "returnUrl"
                 ]
    }
                 
  where
    handleMissingCode =
      throwError err400 {errBody = "Missing code"}
    handleMissingState =
      throwError err400 {errBody = "Missing state"}
    handleInvalidReturnUrl returnUrl =
      throwError err400 {errBody = B.fromStrict $ B.concat
                          [ "Invalid return URL: "
                          , encodeUtf8 returnUrl
                          ]}
    handleDisallowedReturnUrl =
      throwError err400 {errBody = "Disallowed return URL"}
    handleMissingCookies =
      throwError err400 {errBody = "Missing cookies"}
    handleNonMatchingCsrfState fromAssertingParty fromCookie =
      throwError err400 {errBody = B.fromStrict $ B.concat
                          [ "CSRF state does not match; received from asserting party: "
                          , encodeUtf8 fromAssertingParty
                          , "; cookie value: "
                          , encodeUtf8 fromCookie
                          ]}
    handleTokenExchangeError err =
      throwError err500 {errBody = B.fromStrict $ B.concat
                          [ "Token exchange failed: "
                          , encodeUtf8 $ T.pack err
                          ]}
    handleIdTokenError err =
      throwError err500 {errBody = B.fromStrict $ B.concat
                          [ "id_token validation failed: "
                          , encodeUtf8 err
                          ]}
    handleMintingError err =
      throwError err500 {errBody = B.fromStrict $ B.concat
                          [ "Minting failed: "
                          , encodeUtf8 $ T.pack $ show err
                          ]}
    parseAllCookies cs = do
      let parsed = parseCookies (encodeUtf8 cs)
      csrfState <- readCookie parsed "csrfState"
      returnUrl <- readCookie parsed "returnUrl"
      pure (csrfState, returnUrl)
    readCookie :: Cookies -> ByteString -> Handler Text
    readCookie cs n = do
      case lookup n cs of
        Just v -> pure $ decodeUtf8 $ urlDecode False v
        Nothing -> throwError err400 {errBody = "Missing cookie: " <> B.fromStrict n}
    clearCookie n = ("Set-Cookie", B.concat [n, "=; HttpOnly; Secure; SameSite=Lax; Path=/auth/callback; Max-Age=0"])
-- | Successful exchange response; the bounce page reads the assertion
-- field and forwards it to the instance as the @#itoken=@ fragment.
newtype ExchangeResponse = ExchangeResponse
  { assertion :: Text
  } deriving (Generic, Show)

instance A.ToJSON ExchangeResponse

-- | The Teams SSO exchange: swap a validated AAD token (from
-- @getAuthToken@ on the bounce page) for an identity assertion whose
-- audience is the validated @return@ URL's origin. The only supported
-- caller is the same-origin bounce page; there are deliberately no
-- CORS headers, so browsers block every cross-origin caller. Errors
-- follow the @{error, message}@ contract of the consumers' login
-- endpoints so the client-side dispatch is uniform.
teamsExchangeHandler :: AuthEnv -> Maybe Text -> BL.ByteString -> Handler ExchangeResponse
teamsExchangeHandler env mReturn rawToken = do
  let securityConfig = env.securityConfig
  returnUrl <- case mReturn >>= parseAbsoluteURI . T.unpack of
    Nothing -> jsonError err400 "invalid-return" "Missing or unparseable return URL"
    Just u -> pure u
  unless (isAllowedReturnUrl securityConfig.laxReturnUrlCheck securityConfig.allowedReturnDomain returnUrl) $
    jsonError err403 "disallowed-return" "Return URL is outside the trust domain"
  claims <- liftIO (validateEntraToken env.jwksCache securityConfig rawToken)
    >>= either (jsonError err401 "invalid-token" . ("Could not validate token: " <>)) pure
  identity <- either (jsonError err401 "invalid-token") pure (entraIdentity claims)
  identityAssertion <- liftIO (mkIdentityAssertion identity)
  minted <- liftIO (generateIdentityAssertion' securityConfig.authIssuerJwk securityConfig.tokenExpiryDuration (mintedAudience returnUrl) identityAssertion)
    >>= either (jsonError err500 "minting-failed" . T.pack . show) pure
  pure $ ExchangeResponse $ TL.toStrict $ TLE.decodeUtf8 minted

-- | Throw a ServerError whose body follows the @{error, message}@
-- contract shared with the consumers' login endpoints.
jsonError :: forall a. ServerError -> Text -> Text -> Handler a
jsonError baseError code message =
  throwError baseError
    { errBody = A.encode $ A.object ["error" .= code, "message" .= message]
    , errHeaders = [("Content-Type", "application/json")]
    }

-- | Shared back half of both login flows: a validated Entra identity
-- becomes a fresh single-use assertion.
mkIdentityAssertion :: EntraIdentity -> IO IdentityAssertion
mkIdentityAssertion identity = do
  assertionId <- UUID.nextRandom
  pure IdentityAssertion
    { assertionId = assertionId
    , oid = identity.oid
    , upn = identity.upn
    , name = identity.name
    }

-- | The assertion audience for a validated return URL: its origin only.
-- Byte-exact on the consumer side, so both flows must derive it here.
mintedAudience :: URI -> URI
mintedAudience returnUrl = returnUrl { uriPath = "", uriQuery = "", uriFragment = "" }

isAllowedReturnUrl :: Bool -> Text -> URI -> Bool
isAllowedReturnUrl laxReturnUrlCheck allowedPattern returnUrl =
     (uriScheme returnUrl == "https:"
      || (laxReturnUrlCheck && uriScheme returnUrl == "http:"))
  && null (uriFragment returnUrl)
  && maybe False isAllowedUriAuthority (uriAuthority returnUrl)
  where
    isAllowedUriAuthority auth =
         null (uriUserInfo auth)
      && (laxReturnUrlCheck || null (uriPort auth))
      && isAllowedHost (T.pack (uriRegName auth))
    isAllowedHost host =
         allowedPattern == host
      || ("." <> allowedPattern) `T.isSuffixOf` host
      
getAuthorizationUrlWithState :: OAuth2Config -> Text -> ByteString
getAuthorizationUrlWithState config state =
  B.concat
    [ "https://login.microsoftonline.com/"
    , encodeUtf8 config.tenantId
    , "/oauth2/v2.0/authorize?"
    , "client_id="
    , urlEncode False (encodeUtf8 config.clientId)
    , "&response_type=code"
    , "&redirect_uri="
    , urlEncode False (encodeUtf8 config.redirectUri)
    , "&response_mode=query"
    , "&scope=openid%20profile%20email"
    , "&state="
    , urlEncode False (encodeUtf8 state)
    ]
