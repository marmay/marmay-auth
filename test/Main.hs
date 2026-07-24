-- | Protocol tests. The ReplayProtection cases exist because the
-- prune predicate's failure mode is invisible in manual testing: an
-- inverted comparison once shipped inside a fully working login flow
-- (every single login succeeds; only replays behave wrong).
module Main (main) where

import Control.Lens ((^.))
import Crypto.JOSE.JWK (KeyMaterialGenParam (OKPGenParam), OKPCrv (Ed25519), asPublicKey, genJWK)
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.Maybe (fromJust)
import Data.Time (addUTCTime, getCurrentTime)
import Data.UUID (UUID)
import Data.UUID qualified as UUID
import Marmay.Auth.Assertion
  ( IdentityAssertion (..)
  , generateIdentityAssertion'
  , validateIdentityAssertion'
  )
import Marmay.Auth.ReplayProtection (ensureUnconsumed, mkConsumedLog)
import Network.URI (parseAbsoluteURI)
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
          , name = "Erika Musterfrau"
          , office365Id = "erika@example.com"
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
