module GCrypt.AsymmetricCrypto.Data (
    ACData,
) where

import Foreign.Storable
import Foreign.Ptr
import Foreign.Marshal.Utils
import Foreign.Marshal.Alloc

import GCrypt.Base
import GPG.Error

newWith :: Storable a => (Ptr a -> IO b) -> IO (a,b)
newWith f = do
    p <- malloc
    r <- f p
    p' <- peek p
    return (p',r)

newData :: IO (Either GCry_Error ACData)
newData = do
    (p,r) <- newWith (gcry_ac_data_new . ACDataPtr)
    case (toIntEnum r) of
         GPG_ERR_NO_ERROR -> return $ Right p
         _ -> return $ Left r
