-- M6 Sybil filter: permanent first-funder cache (Research4-M6-sybil.md §1, §5).
-- One row per (chain, address) — reviewers AND their funder-ancestry nodes
-- (the engine walks funding ancestry to cluster by root). A first funder
-- never changes once an address is active on-chain, so rows are written once
-- and read forever — that permanence is what keeps the Alchemy budget
-- trivial. Lookup FAILURES are never cached (no 'error' status): a missing
-- row means "not resolved yet", and the next sybil pass retries it. Known
-- accepted risk: a 'none' written while the provider's transfer index lags
-- the chain head would stick; the window is seconds-to-minutes and the
-- affected wallet must have been funded immediately before its first-ever
-- lookup.
CREATE TABLE reviewer_funding (
    chain_id           INTEGER NOT NULL,     -- chain the lookup ran on (8453 = Base)
    address            TEXT NOT NULL,        -- lowercased reviewer address
    status             TEXT NOT NULL CHECK (status IN ('ok', 'none')),
                                             -- ok   = earliest inbound external native
                                             --        transfer found (funder set)
                                             -- none = no such transfer exists (funded
                                             --        via internal/contract path) —
                                             --        permanent: the address is already
                                             --        active, so its funding happened
    funder             TEXT,                 -- lowercased first-funder, NULL unless ok
    funder_is_contract INTEGER,              -- eth_getCode on funder: 0 = EOA (incl.
                                             -- EIP-7702 delegated), 1 = contract;
                                             -- NULL unless status = ok
    tx_hash            TEXT,                 -- the funding transaction, NULL unless ok
    block_num          INTEGER,              -- its block, NULL unless ok
    looked_up_at       TEXT NOT NULL,
    PRIMARY KEY (chain_id, address)
) STRICT, WITHOUT ROWID;

-- The fan-out hub heuristic groups by funder.
CREATE INDEX idx_reviewer_funding_funder
    ON reviewer_funding(chain_id, funder) WHERE funder IS NOT NULL;

-- Which agents each reviewer left feedback on. Powers the CROSS-AGENT fan-out
-- hub heuristic: a funder whose funded reviewers span many distinct agents is
-- de-facto infrastructure (unlabeled CEX/bridge hot wallet) and must not
-- cluster them. Within ONE agent's reviewer set, a shared funder is the Sybil
-- signal itself — never hub evidence — which is why the heuristic needs this
-- table instead of a plain per-funder reviewer count.
CREATE TABLE reviewer_agents (
    chain_id        INTEGER NOT NULL,
    address         TEXT NOT NULL,           -- lowercased reviewer address
    agent_global_id TEXT NOT NULL,           -- subgraph entity id "<chainId>:<agentId>"
    PRIMARY KEY (chain_id, address, agent_global_id)
) STRICT, WITHOUT ROWID;
