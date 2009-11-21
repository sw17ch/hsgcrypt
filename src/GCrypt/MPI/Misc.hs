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

setFlag :: MPI -> MPIFlag -> IO ()
setFlag = gcry_mpi_set_flag

getFlag :: MPI -> MPIFlag -> IO CInt
getFlag = gcry_mpi_get_flag

clearFlag :: MPI -> MPIFlag -> IO ()
clearFlag = gcry_mpi_clear_flag

randomize :: MPI -> CUInt -> GCry_Random_Level -> IO ()
randomize = gcry_mpi_randomize
