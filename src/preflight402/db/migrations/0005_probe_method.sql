-- Persist WHICH HTTP method produced each probe row.
--
-- ProbeResult.method already existed in memory (surfaced in the trust-preview
-- health block) but was never stored, so the M3 checkpoint could not tell a
-- GET-derived verdict from a POST-fallback one — which is exactly the
-- distinction that mattered when the GET-only gap was found
-- (docs/checkpoint-m3.md). Storing it makes the fix measurable: the share of
-- 402s recovered by the POST retry is now a query, not a re-probing campaign.
--
-- NULL for rows written before this migration (and for 'blocked' rows, where
-- no request was made). New rows always carry GET or POST.
ALTER TABLE probes ADD COLUMN method TEXT;

-- What a POST retry answered when its result was NOT kept (only a 402 is
-- kept). Makes the retry auditable: 'retried and got 404' is now
-- distinguishable from 'never retried', which method alone cannot express,
-- and a 429 here is the host telling us to back off.
ALTER TABLE probes ADD COLUMN retry_status INTEGER;
