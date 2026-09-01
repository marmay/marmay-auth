{-# LANGUAGE RecordWildCards #-}

module Marmay.Auth.SecurityConfig
  ( SecurityConfig (.. )
  , TeamsConfig (..)
  , ApplicationEntry (..)
  , ViewEntry (..)
  , loadSecurityConfig
  )
  where

import GHC.Generics (Generic)
import Marmay.Auth.OAuth2Config
import Data.Aeson (FromJSON(..), ToJSON, withObject, (.:), (.:?), (.!=))
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
  , frameAncestors :: ![Text]
    -- ^ Origins allowed to iframe the Teams pages (frame-ancestors
    --   sources). Defaults to the Microsoft host list; override only
    --   when Microsoft's hosting domains churn.
  }
  deriving (Generic, Show)

-- | One selectable application of the "BG Horn" meta-app. A tab shows
-- one view of one application: the selector is two-stage (application,
-- then view), and the tab's target is @url <> view.path@. The target
-- must allow Teams framing and run the frame-aware bootstrap core.
-- NOT part of 'SecurityConfig': the registry is public data, loaded
-- from a separate unencrypted file (nix-store-rendered) via
-- 'Marmay.Auth.ConfigFile.loadPublicConfigFile'.
data ApplicationEntry = ApplicationEntry
  { name :: !Text
  , url :: !Text
    -- ^ Base URL (origin) of the application, no trailing slash.
  , views :: ![ViewEntry]
  }
  deriving (Generic, Show)

instance FromJSON ApplicationEntry
instance ToJSON ApplicationEntry

-- | One view of an application: a path (relative to the application's
-- base URL, query strings allowed — e.g. @/app/assignments?embedded@).
data ViewEntry = ViewEntry
  { name :: !Text
  , path :: !Text
  }
  deriving (Generic, Show)

instance FromJSON ViewEntry
instance ToJSON ViewEntry

defaultTeamsFrameAncestors :: [Text]
defaultTeamsFrameAncestors =
  [ "teams.microsoft.com"
  , "*.teams.microsoft.com"
  , "*.office.com"
  , "*.microsoft365.com"
  , "*.cloud.microsoft"
  ]

defaultTeamsConfig :: TeamsConfig
defaultTeamsConfig = TeamsConfig
  { applicationIdUri = Nothing
  , frameAncestors = defaultTeamsFrameAncestors
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

instance FromJSON TeamsConfig where
  -- Manual instance so a present-but-partial "teamsConfig" object
  -- still picks up the defaults for omitted keys.
  parseJSON = withObject "TeamsConfig" $ \o -> do
    applicationIdUri <- o .:? "applicationIdUri"
    frameAncestors <- o .:? "frameAncestors" .!= defaultTeamsFrameAncestors
    pure TeamsConfig {..}

loadSecurityConfig :: FilePath -> IO SecurityConfig
loadSecurityConfig = forceLoadConfigFile @SecurityConfig
