module GCrypt.Generalities.Error.Strings (
    strerror,
    strsource,
) where

import GCrypt.Base
import Foreign.C.String

strerror :: GCry_Error -> IO String
strerror e = gcry_strerror e >>= peekCString

strsource :: GCry_Error -> IO String
strsource e = gcry_strsource e >>= peekCString
