module GCrypt.AsymmetricCrypto.IO (
    initReadableString,
    initWritableString,
    ACIOPtr,
) where

import Foreign.Ptr
import Foreign.C.Types

import GCrypt.Base

initReadableString :: ACIOPtr -> Ptr CUChar -> CULong -> IO ()
initReadableString = gcry_ac_io_init_readable_string

initWritableString :: ACIOPtr -> Ptr (Ptr CUChar) -> Ptr CULong -> IO ()
initWritableString = gcry_ac_io_init_writable_string

