module GCrypt (
    withGCrypt,
) where

import GCrypt.Base
import Foreign.Ptr
import Foreign.C.String

withGCrypt :: IO a -> IO a
withGCrypt a = do
    checkVersion "1.4.4"
    a

checkVersion :: String -> IO (Maybe String)
checkVersion s = do
    r <- withCString s $ \s' -> gcry_check_version s'
    case r == nullPtr of
        True -> return Nothing
        False -> peekCString r >>= return . Just 
