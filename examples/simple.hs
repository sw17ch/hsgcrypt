module Main where

import GCrypt.AsymmetricCrypto.Data

main :: IO ()
main = do
    (Right d) <- newData
    print d
    destroyData d
