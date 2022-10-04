{-# LANGUAGE OverloadedStrings #-}

module LookupSpec where

import Test.Hspec

import DNS.IO as DNS
import DNS.IO.Resolver

spec :: Spec
spec = describe "lookup" $ do

    it "lookupA" $ do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \resolver -> do
            addrs <- DNS.lookupA resolver "mew.org"
            -- mew.org has one or more IPv6 addresses
            fmap null addrs `shouldBe` Right False

    it "lookupAAAA" $ do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \resolver -> do
            -- google.com has one or more IPv6 addresses
            addrs <- DNS.lookupAAAA resolver "google.com"
            fmap null addrs `shouldBe` Right False

    it "lookupAAAA with emty result" $ do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \resolver -> do
            addrs <- DNS.lookupAAAA resolver "ipv4.tlund.se"
            -- mew.org does not have any IPv6 addresses
            fmap null addrs `shouldBe` Right True

    it "lookupMX" $ do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \resolver -> do
            addrs <- DNS.lookupMX resolver "mew.org"
            -- mew.org has one or more MX records.
            fmap null addrs `shouldBe` Right False

    it "lookupTXT" $ do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \resolver -> do
            addrs <- DNS.lookupTXT resolver "mew.org"
            -- mew.org has one or more TXT records.
            fmap null addrs `shouldBe` Right False

    it "lookupSOA" $ do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \resolver -> do
            addrs <- DNS.lookupTXT resolver "mew.org"
            -- mew.org has a SOA record.
            fmap null addrs `shouldBe` Right False

    it "lookupNS" $ do
        rs <- makeResolvSeed defaultResolvConf
        withResolver rs $ \resolver -> do
            addrs <- DNS.lookupNS resolver "mew.org"
            -- mew.org has one or more NS records.
            fmap null addrs `shouldBe` Right False
