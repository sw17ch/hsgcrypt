module GCrypt.AsymmetricCrypto.Data (
    ACData,
    dataNew,
    dataDestroy,
    dataSet,
    dataCopy,
    dataLength,
) where

import Foreign.C.String
import Foreign.Ptr
import Data.Word

import GCrypt.Util

import GCrypt.Base
import GPG.Error


-- Helper for newWithChecked. If the error returned
-- is GPG_ERR_NO_ERROR, then we return the pointer,
-- else we return the error number.
checkData :: GCry_Error -> Bool
checkData e = (toIntEnum e) == GPG_ERR_NO_ERROR

-- |gcry_ac_data_new
dataNew :: IO (Either GCry_Error ACData)
dataNew = do
    newWithChecked f checkData
    where
        f :: Ptr ACData -> IO GCry_Error
        f = gcry_ac_data_new . ACDataPtr

dataDestroy :: ACData -> IO ()
dataDestroy = gcry_ac_data_destroy
   
dataSet :: ACData -> ACFlags -> CString -> MPI -> IO GCry_Error
dataSet = gcry_ac_data_set

dataCopy :: ACData -> IO (Either GCry_Error ACData)
dataCopy d = do
    newWithChecked f checkData
    where
        f :: Ptr ACData -> IO GCry_Error
        f p = gcry_ac_data_copy (ACDataPtr p) d

dataLength :: ACData -> IO Word32
dataLength = gcry_ac_data_length

