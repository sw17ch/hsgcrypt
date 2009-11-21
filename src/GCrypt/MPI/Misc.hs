module GCrypt.MPI.Misc (
    setOpaque,
    getOpaque,
    setFlag,
    clearFlag,
    getFlag,
    randomize,
) where

import Foreign.Ptr
import Foreign.C.Types

import GCrypt.Base

setOpaque :: MPI -> Ptr () -> CUInt -> IO MPI
setOpaque = gcry_mpi_set_opaque

getOpaque :: MPI -> Ptr CUInt -> IO (Ptr ())
getOpaque = gcry_mpi_get_opaque

setFlag :: MPI -> GCry_MPI_Flag -> IO ()
setFlag = gcry_mpi_set_flag

getFlag :: MPI -> GCry_MPI_Flag -> IO CInt
getFlag = gcry_mpi_get_flag

clearFlag :: MPI -> GCry_MPI_Flag -> IO ()
clearFlag = gcry_mpi_clear_flag

randomize :: MPI -> CUInt -> GCry_Random_Level -> IO ()
randomize = gcry_mpi_randomize
