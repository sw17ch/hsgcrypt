module GCrypt.AsymmetricCrypto.Data (
    ACData,
    newData,
    destroyData,
) where

import Foreign.Storable
import Foreign.Ptr
import Foreign.Marshal.Utils
import Foreign.Marshal.Alloc

import GCrypt.Base
import GPG.Error

-- |Often times, we need to allocate something and
-- pass it to a function and keep the allocated object
-- around. The function we pass it to is the initializer.
newWith :: Storable a => (Ptr a -> IO b) -> IO (a,b)
newWith f = do
    p <- malloc
    r <- f p
    p' <- peek p
    free p
    return (p',r)

-- |gcry_ac_data_new
newData :: IO (Either GCry_Error ACData)
newData = do
    (p,r) <- newWith (gcry_ac_data_new . ACDataPtr)
    case (toIntEnum r) of
         GPG_ERR_NO_ERROR -> return $ Right p
         _ -> return $ Left r

destroyData :: ACData -> IO ()
destroyData = gcry_ac_data_destroy
    
