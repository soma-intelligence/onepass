-- OnePass mailbox: no JIT in the blob batch functions.
--
-- The planner estimates the storage.objects check of api_blob_announce at
-- over six million cost units for a batch of 1000 blobs, far above
-- jit_above_cost. On a server built with LLVM (Postgres from PGDG, as on
-- CI), JIT compilation then took 1122 ms of a 1128 ms statement, and the
-- largest announce batch 2.2 s instead of about 25 ms. These functions run
-- short queries over at most 1000 rows: compiling them never pays off.

alter function onepass_mailbox.api_blob_announce(
    bytea, bytea, timestamptz, bytea, bytea[], integer[])
    set jit = off;

alter function onepass_mailbox.api_blob_lookup(
    bytea, bytea, timestamptz, bytea, bytea[])
    set jit = off;
