{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Prometheus where

import Data.ByteString.Builder
import qualified Data.ByteString.Lazy.Char8 as BL
import GHC.Stats

toB :: Show a => a -> Builder
toB = lazyByteString . BL.pack . show

{- FOURMOLU_DISABLE -}
fromRTSStats :: RTSStats -> Builder
fromRTSStats RTSStats{..} =
    "ghc_gcs " <> toB gcs <> "\n"
 <> "ghc_ghc_major_gcs " <> toB major_gcs <> "\n"
 <> "ghc_allocated_bytes " <> toB allocated_bytes <> "\n"
 <> "ghc_max_live_bytes " <> toB max_live_bytes <> "\n"
 <> "ghc_max_large_objects_bytes " <> toB max_large_objects_bytes <> "\n"
 <> "ghc_max_compact_bytes " <> toB max_compact_bytes <> "\n"
 <> "ghc_max_slop_bytes " <> toB max_slop_bytes <> "\n"
 <> "ghc_max_mem_in_use_bytes " <> toB max_mem_in_use_bytes <> "\n"
 <> "ghc_cumulative_live_bytes " <> toB cumulative_live_bytes <> "\n"
 <> "ghc_copied_bytes " <> toB copied_bytes <> "\n"
 <> "ghc_par_copied_bytes " <> toB par_copied_bytes <> "\n"
 <> "ghc_cumulative_par_max_copied_bytes " <> toB cumulative_par_max_copied_bytes <> "\n"
 <> "ghc_cumulative_par_balanced_copied_bytes " <> toB cumulative_par_balanced_copied_bytes <> "\n"
 <> "ghc_init_cpu_ns " <> toB init_cpu_ns <> "\n"
 <> "ghc_init_elapsed_ns " <> toB init_elapsed_ns <> "\n"
 <> "ghc_mutator_cpu_ns " <> toB mutator_cpu_ns <> "\n"
 <> "ghc_mutator_elapsed_ns " <> toB mutator_elapsed_ns <> "\n"
 <> "ghc_gc_cpu_ns " <> toB gc_cpu_ns <> "\n"
 <> "ghc_gc_elapsed_ns " <> toB gc_elapsed_ns <> "\n"
 <> "ghc_cpu_ns " <> toB cpu_ns <> "\n"
 <> "ghc_elapsed_ns " <> toB elapsed_ns <> "\n"
{-
 <> "ghc_nonmoving_gc_sync_cpu_ns " <> toB nonmoving_gc_sync_cpu_ns <> "\n"
 <> "ghc_nonmoving_gc_sync_elapsed_ns " <> toB nonmoving_gc_sync_elapsed_ns <> "\n"
 <> "ghc_nonmoving_gc_sync_max_elapsed_ns " <> toB nonmoving_gc_sync_max_elapsed_ns <> "\n"
 <> "ghc_nonmoving_gc_cpu_ns " <> toB nonmoving_gc_cpu_ns <> "\n"
 <> "ghc_nonmoving_gc_elapsed_ns " <> toB nonmoving_gc_elapsed_ns <> "\n"
 <> "ghc_nonmoving_gc_max_elapsed_ns " <> toB nonmoving_gc_max_elapsed_ns <> "\n"
-}
 <> "ghc_gcdetails_gen " <> toB gcdetails_gen <> "\n"
 <> "ghc_gcdetails_threads " <> toB gcdetails_threads <> "\n"
 <> "ghc_gcdetails_allocated_bytes " <> toB gcdetails_allocated_bytes <> "\n"
 <> "ghc_gcdetails_live_bytes " <> toB gcdetails_live_bytes <> "\n"
 <> "ghc_gcdetails_large_objects_bytes " <> toB gcdetails_large_objects_bytes <> "\n"
 <> "ghc_gcdetails_compact_bytes " <> toB gcdetails_compact_bytes <> "\n"
 <> "ghc_gcdetails_slop_bytes " <> toB gcdetails_slop_bytes <> "\n"
 <> "ghc_gcdetails_mem_in_use_bytes " <> toB gcdetails_mem_in_use_bytes <> "\n"
 <> "ghc_gcdetails_copied_bytes " <> toB gcdetails_copied_bytes <> "\n"
 <> "ghc_gcdetails_par_max_copied_bytes " <> toB gcdetails_par_max_copied_bytes <> "\n"
 <> "ghc_gcdetails_par_balanced_copied_bytes " <> toB gcdetails_par_balanced_copied_bytes <> "\n"
{-
 <> "ghc_gcdetails_block_fragmentation_bytes " <> toB gcdetails_block_fragmentation_bytes <> "\n"
-}
 <> "ghc_gcdetails_sync_elapsed_ns " <> toB gcdetails_sync_elapsed_ns <> "\n"
 <> "ghc_gcdetails_cpu_ns " <> toB gcdetails_cpu_ns <> "\n"
 <> "ghc_gcdetails_elapsed_ns " <> toB gcdetails_elapsed_ns <> "\n"
 <> "ghc_gcdetails_nonmoving_gc_sync_cpu_ns " <> toB gcdetails_nonmoving_gc_sync_cpu_ns <> "\n"
 <> "ghc_gcdetails_nonmoving_gc_sync_elapsed_ns " <> toB gcdetails_nonmoving_gc_sync_elapsed_ns <> "\n"
  where
    GCDetails{..} = gc
{- FOURMOLU_ENABLE -}
