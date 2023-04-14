{-# LANGUAGE OverloadedStrings #-}

module LookupSpec where

import Test.Hspec

import DNS.Do53.Client as DNS

spec :: Spec
spec = describe "lookup" $ do

    it "lookupA" $ do
        withLookupConf defaultLookupConf $ \resolver -> do
            addrs <- DNS.lookupA resolver "mew.org"
            -- mew.org has one or more IPv6 addresses
            fmap null addrs `shouldBe` Right False

    it "lookupAAAA" $ do
        withLookupConf defaultLookupConf $ \resolver -> do
            -- google.com has one or more IPv6 addresses
            addrs <- DNS.lookupAAAA resolver "google.com"
            fmap null addrs `shouldBe` Right False

    it "lookupAAAA with empty result" $ do
        withLookupConf defaultLookupConf $ \resolver -> do
            addrs <- DNS.lookupAAAA resolver "ipv4.tlund.se"
            fmap null addrs `shouldBe` Right True

    it "lookupMX" $ do
        withLookupConf defaultLookupConf $ \resolver -> do
            addrs <- DNS.lookupMX resolver "mew.org"
            -- mew.org has one or more MX records.
            fmap null addrs `shouldBe` Right False

    it "lookupTXT" $ do
        withLookupConf defaultLookupConf $ \resolver -> do
            addrs <- DNS.lookupTXT resolver "mew.org"
            -- mew.org has one or more TXT records.
            fmap null addrs `shouldBe` Right False

    it "lookupSOA" $ do
        withLookupConf defaultLookupConf $ \resolver -> do
            addrs <- DNS.lookupTXT resolver "mew.org"
            -- mew.org has a SOA record.
            fmap null addrs `shouldBe` Right False

    it "lookupNS" $ do
        withLookupConf defaultLookupConf $ \resolver -> do
            addrs <- DNS.lookupNS resolver "mew.org"
            -- mew.org has one or more NS records.
            fmap null addrs `shouldBe` Right False
