module Main where

import Data.ByteString.Char8

import GCrypt
import GCrypt.AsymmetricCrypto.Crypto

main :: IO ()
main = withGCrypt $ do
    (Right e1) <- dataEMEEncode emeopt str
    print e1
    d1 <- dataEMEDecode emeopt e1
    print d1

    e2 <- dataEMSAEncode (OptionsEMSA MD_SHA256 len) str
    print e2
    where
        emeopt = OptionsEME len
        emsaopt = OptionsEMSA MD_SHA256 len
        len = 1024
        str = pack "Hello World"
