module Main where

import GCrypt.AsymmetricCrypto.Data

main :: IO ()
main = do
    (Right d) <- dataNew
    print d
    dataDestroy d
