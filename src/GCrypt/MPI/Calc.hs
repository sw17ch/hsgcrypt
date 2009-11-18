module GCrypt.MPI.Calc (
) where

import GCrypt.Base

-- |w = u + v
add :: MPI -> MPI -> MPI -> IO ()
add w u v = gcry_mpi_add w u v
