module GCrypt.MPI.Calc (
    ULong,
    add, addUi, addm,
    mul, mulUi, mulm, mul2exp,
    div, mod, powm,
    gcd, invm,
) where

-- |Some functions in this module clash with names
-- in prelude. At the very least this includes div
-- and mod. To get around this problem, we can use
-- two import statements for this module:
--
-- > import qualified GCrypt.MPI.Calc as C
-- > import GCrypt.MPI.Calc hiding (mod, div)
--
-- This allows us use the qualified names for mod
-- and div but ignore it for everything else.

import Prelude hiding (div,mod,gcd)
import Data.Int
import Control.Monad

import GCrypt.Base
import GCrypt.Util

-- |w = u + v
add :: MPI -> MPI -> MPI -> IO ()
add = gcry_mpi_add

-- |w = u + v (v is an unsigned long)
addUi :: MPI -> MPI -> ULong -> IO ()
addUi = gcry_mpi_add_ui

-- |w = u + (v `mod` m)
addm :: MPI -> MPI -> MPI -> MPI -> IO ()
addm = gcry_mpi_addm

-- |w = u + v
mul :: MPI -> MPI -> MPI -> IO ()
mul = gcry_mpi_mul

-- |w = u + v (v is an unsigned long)
mulUi :: MPI -> MPI -> ULong -> IO ()
mulUi = gcry_mpi_mul_ui

-- |w = u + (v `mod` m)
mulm :: MPI -> MPI -> MPI -> MPI -> IO ()
mulm = gcry_mpi_mulm

mul2exp :: MPI -> MPI -> ULong -> IO ()
mul2exp = gcry_mpi_mul_2exp

div :: MPI -> MPI -> MPI -> MPI -> Int32 -> IO ()
div q r dividend divisor rnd = gcry_mpi_div q r dividend divisor round'
    where round' = fromIntegral rnd

mod :: MPI -> MPI -> MPI -> IO ()
mod = gcry_mpi_mod

powm :: MPI -> MPI -> MPI -> MPI -> IO ()
powm = gcry_mpi_powm

-- |Set g equal to the gcd of a and b.
-- Returns true if g is 1.
gcd :: MPI -> MPI -> MPI -> IO Bool
gcd g a b = do r <- gcry_mpi_gcd g a b
               return $ not (r == 0)
                
-- |Set x to the mulplicative inverse of a `mod` b. Retrun true
-- if the inverse exists.
invm :: MPI -> MPI -> MPI -> IO Int32
invm x a m = gcry_mpi_invm x a m >>= return . fromIntegral
