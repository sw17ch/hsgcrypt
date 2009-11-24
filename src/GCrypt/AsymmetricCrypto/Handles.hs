module GCrypt.AsymmetricCrypto.Handles (
    ACHandle,
    acOpen,
    acClose,
) where

import Foreign.Ptr

import GCrypt.Base
import GCrypt.Util
import GPG.Error

checkData :: GCry_Error -> Bool
checkData e = (toIntEnum e) == GPG_ERR_NO_ERROR

acOpen :: GCry_AC_ID -> ACFlags -> IO (Either GCry_Error ACHandle)
acOpen alg fl = do
    newWithChecked f checkData
    where
        f :: Ptr ACHandle -> IO GCry_Error
        f p = gcry_ac_open (ACHandlePtr p) alg fl

acClose :: ACHandle -> IO ()
acClose = gcry_ac_close
