module Marmay.Auth.OAuth2Config
  ( OAuth2Config( .. )
  ) where

import Data.Text (Text)
import GHC.Generics (Generic)
import Data.Aeson (FromJSON)

-- | OAuth2 configuration from file
data OAuth2Config = OAuth2Config
  { clientId :: !Text
  , clientSecret :: !Text
  , redirectUri :: !Text
  , tenantId :: !Text
  }
  deriving (Generic, Show)

instance FromJSON OAuth2Config
