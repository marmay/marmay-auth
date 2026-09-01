-- | The server-to-server half of the authorization-code flow: redeem
-- the code at the AAD token endpoint. Identity comes from the
-- id_token in the response (validated by
-- "Marmay.Auth.Microsoft.AuthTokenValidator"); no Graph call is made.
module Marmay.Auth.Microsoft.CodeExchange
  ( exchangeCodeForIdToken
  ) where

import Marmay.Auth.OAuth2Config (OAuth2Config(..))
import qualified Data.Aeson as A
import qualified Data.Aeson.KeyMap as A
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Network.HTTP.Client as H
import qualified Network.HTTP.Types as H
import Network.HTTP.Client (Manager)

-- | Exchange an authorization code for the id_token of the response.
exchangeCodeForIdToken :: Manager -> OAuth2Config -> T.Text -> IO (Either String T.Text)
exchangeCodeForIdToken tlsManager config code = do
  let tokenUrl = T.concat
        [ "https://login.microsoftonline.com/"
        , config.tenantId
        , "/oauth2/v2.0/token"
        ]

  request <- H.parseRequest $ T.unpack tokenUrl
  let body = T.concat
        [ "client_id=" <> config.clientId
        , "&client_secret=" <> config.clientSecret
        , "&code=" <> code
        , "&redirect_uri=" <> config.redirectUri
        , "&grant_type=authorization_code"
        ]

  let request' = request
        { H.requestHeaders = [(H.hContentType, "application/x-www-form-urlencoded")]
        , H.method = "POST"
        , H.requestBody = H.RequestBodyBS (T.encodeUtf8 body)
        }

  response <- H.httpLbs request' tlsManager

  case A.eitherDecode (H.responseBody response) of
    Left err -> pure $ Left $ "Failed to parse token response: " <> err
    Right (A.Object obj) -> case A.lookup "id_token" obj of
      Just (A.String token) -> pure $ Right token
      _ -> pure $ Left "No id_token in response"
    Right _ -> pure $ Left "Invalid token response format"
