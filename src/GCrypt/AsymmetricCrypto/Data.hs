module GCrypt.AsymmetricCrypto.Data (
    ACData,
    dataNew,
    dataDestroy,
    dataSet,
    dataCopy,
    dataLength,
    dataGetName,
    dataGetIndex,
    dataToSExp,
    dataFromSExp,
    DataIndex,
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

dataGetName :: ACData -> ACFlags -> CString -> IO (Either GCry_Error MPI)
dataGetName d fl n = do
    newWithChecked f checkData
    where
        f :: Ptr MPI -> IO GCry_Error
        f p = gcry_ac_data_get_name d fl n (MPIPtr p)

dataGetIndex :: ACData -> ACFlags -> DataIndex -> IO (Either GCry_Error (CString,MPI))
dataGetIndex d fl i = do
    newWith2Checked f checkData
    where
        f :: Ptr CString -> Ptr MPI -> IO GCry_Error
        f s m = gcry_ac_data_get_index d fl i s (MPIPtr m)

dataClear :: ACData -> IO ()
dataClear = gcry_ac_data_clear

dataToSExp :: ACData -> Ptr (CString) -> IO (Either GCry_Error SExp)
dataToSExp d cp = do
    newWithChecked f checkData
    where
        f :: Ptr SExp -> IO GCry_Error
        f sp = gcry_ac_data_to_sexp d (SExpPtr sp) cp

dataFromSExp :: SExp -> Ptr (CString) -> IO (Either GCry_Error ACData)
dataFromSExp s cp = do
    newWithChecked f checkData
    where
        f :: Ptr ACData -> IO GCry_Error
        f ap = gcry_ac_data_from_sexp (ACDataPtr ap) s cp
