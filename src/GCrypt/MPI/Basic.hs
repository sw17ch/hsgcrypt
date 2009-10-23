module GCrypt.MPI.Basic (
    mpiNew,
    mpiSNew,
    mpiCopy,
    mpiRelease,
    mpiSet,
    mpiSetUI,
) where

import Data.Word
import Foreign.Ptr

import GCrypt.Base

mpiNew :: Word32 -> IO MPI
mpiNew = gcry_mpi_new . fromIntegral

mpiSNew :: Word32 -> IO MPI
mpiSNew = gcry_mpi_snew . fromIntegral

mpiCopy :: MPI -> IO MPI
mpiCopy = gcry_mpi_copy

mpiRelease :: MPI -> IO ()
mpiRelease = gcry_mpi_release

mpiSet :: Maybe MPI -> MPI -> IO MPI
mpiSet w u = do
    gcry_mpi_set w' u
    where
        w' = case w of
                (Just p) -> p
                Nothing -> MPI nullPtr

mpiSetUI :: Maybe MPI -> Int -> IO MPI
mpiSetUI w u = do
    gcry_mpi_set_ui w' (fromIntegral u)
    where
        w' = case w of
                (Just p) -> p
                Nothing -> MPI nullPtr

mpiSwap :: MPI -> MPI -> IO ()
mpiSwap = gcry_mpi_swap
