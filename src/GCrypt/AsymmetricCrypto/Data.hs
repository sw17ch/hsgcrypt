module GCrypt.AsymmetricCrypto.Data (
    ACData,
    dataNew,
    dataDestroy,
) where

import Foreign.Storable
import Foreign.Ptr
import Foreign.Marshal.Utils
import Foreign.Marshal.Alloc

import GCrypt.Util

import GCrypt.Base
import GPG.Error

-- |gcry_ac_data_new
dataNew :: IO (Either GCry_Error ACData)
dataNew = do
    (p,r) <- newWith (gcry_ac_data_new . ACDataPtr)
    case (toIntEnum r) of
         GPG_ERR_NO_ERROR -> return $ Right p
         _ -> return $ Left r

dataDestroy :: ACData -> IO ()
dataDestroy = gcry_ac_data_destroy
   
