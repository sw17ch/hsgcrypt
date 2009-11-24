module GCrypt.AsymmetricCrypto.IO (
    initReadableString,
    initWritableString,
    ACIO,
) where

import Foreign.Ptr
import Foreign.C.Types

import GCrypt.Base

initReadableString :: ACIO -> Ptr CUChar -> CULong -> IO ()
initReadableString = gcry_ac_io_init_readable_string

initWritableString :: ACIO -> Ptr (Ptr CUChar) -> Ptr CULong -> IO ()
initWritableString = gcry_ac_io_init_writable_string

