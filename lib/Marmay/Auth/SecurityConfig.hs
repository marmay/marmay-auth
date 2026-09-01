{-# LANGUAGE RecordWildCards #-}

module Marmay.Auth.SecurityConfig
  ( SecurityConfig (.. )
  , TeamsConfig (..)
  , loadSecurityConfig
  )
  where

import GHC.Generics (Generic)
import Marmay.Auth.OAuth2Config
import Data.Aeson (FromJSON(..), withObject, (.:), (.:?), (.!=))
import qualified Crypto.JOSE as JOSE
import Marmay.Auth.ConfigFile (forceLoadConfigFile)
import Data.Time (NominalDiffTime)
import Data.Text (Text)

data SecurityConfig = SecurityConfig
  { oauth2Config :: !OAuth2Config
  , authIssuerJwk :: !JOSE.JWK
  , allowedReturnDomain :: !Text
  , tokenExpiryDuration :: !NominalDiffTime
  , teamsConfig :: !TeamsConfig
  , laxReturnUrlCheck :: !Bool
  }
  deriving (Generic, Show)

data TeamsConfig = TeamsConfig
  { applicationIdUri :: !(Maybe Text)
    -- ^ Application-ID URI of the App registration in Entra.
    --   Only required for a fallback case, when verifying tokens,
    --   usually can be omitted.
  }
  deriving (Generic, Show)

defaultTeamsConfig :: TeamsConfig
defaultTeamsConfig = TeamsConfig
  { applicationIdUri = Nothing
  }

instance FromJSON SecurityConfig where
  -- Manual parseJSON with default values for tokenExpiryDuration and laxReturnUrlCheck:
  parseJSON = withObject "SecurityConfig" $ \o -> do
    oauth2Config <- o .: "oauth2Config"
    authIssuerJwk <- o .: "authIssuerJwk"
    allowedReturnDomain <- o .: "allowedReturnDomain"
    tokenExpiryDuration <- o .:? "tokenExpiryDuration" .!= 60
    teamsConfig <- o .:? "teamsConfig" .!= defaultTeamsConfig
    laxReturnUrlCheck <- o .:? "laxReturnUrlCheck" .!= False
    pure SecurityConfig {..}

instance FromJSON TeamsConfig

loadSecurityConfig :: FilePath -> IO SecurityConfig
loadSecurityConfig = forceLoadConfigFile @SecurityConfig
