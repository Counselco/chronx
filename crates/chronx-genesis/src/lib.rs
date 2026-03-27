//! chronx-genesis
//!
//! Builds the ChronX genesis state from scratch, writing directly into a
//! `StateDb` without going through the normal transaction engine (genesis
//! transactions have no parents and no PoW — they are the founding document).
//!
//! Genesis allocations v8.0 (all at GENESIS_TIMESTAMP = 2026-01-01 00:00:00 UTC):
//!
//! Genesis allocations (6 entries only — all at GENESIS_TIMESTAMP = 2026-01-01 00:00:00 UTC):
//!
//! 1.  Public sale address — 6,093,000,000 KX  (spendable immediately)
//! 2.  Treasury — 1,000,000,000 KX  (100 annual time-locks, log-declining)
//! 3.  Node Rewards — 1,000,000,000 KX  (100 annual time-locks, log-declining)
//! 4.  Humanity stake —     1,000,000 KX  (single lock until 2126-01-01, own wallet)
//! 5.  Milestone 2076 —       500,000 KX  (unlocks 2076-01-01, own wallet)
//! 6.  Protocol reserve —       500,000 KX  (unlocks 2036-01-01, own wallet)
//!
//! Genesis block total: 8,095,000,000 KX
//! Remaining 175,000,000 KX sits in Public Sale, distributed post-genesis:
//!   Founder 188M, Faucet 3M, MISAI Bond 10M, Verifas Bond 10M, + community wallets
//!
//! Total supply: 8,270,000,000 KX

pub mod params;

pub use params::GenesisParams;

use chronx_core::account::{Account, AuthPolicy, TimeLockContract, TimeLockStatus};
use chronx_core::constants::{
    CHRONOS_PER_KX, FAUCET_KX, FOUNDER_KX, GENESIS_TIMESTAMP, HUMANITY_STAKE_KX,
    HUMANITY_UNLOCK_TIMESTAMP, MILESTONE_2076_KX, MILESTONE_2076_UNLOCK_TIMESTAMP, MISAI_BOND_KX,
    NODE_REWARDS_KX, PROTOCOL_RESERVE_KX, PROTOCOL_RESERVE_UNLOCK_TIMESTAMP, PUBLIC_SALE_KX,
    TREASURY_KX, VERIFAS_BOND_KX,
};
use chronx_core::error::ChronxError;
use chronx_core::types::{AccountId, TxId};
use chronx_state::StateDb;
use chronx_timelock::{node_rewards_release_schedule, treasury_release_schedule};
use tracing::info;

/// Seed accounts used in genesis.
pub struct GenesisAccounts {
    /// Receives the public sale allocation. Real key supplied at launch.
    pub public_sale: AccountId,
    /// Holds the 100-year treasury time-locks. Governance-controlled.
    pub treasury: AccountId,
    /// Holds the 100-year node rewards time-locks.
    pub node_rewards: AccountId,
    /// The humanity stake recipient. Long-horizon public key.
    pub humanity: AccountId,
    /// Founder allocation .
    pub founder: AccountId,
    /// MISAI Bond allocation .
    pub misai: AccountId,
    /// Verifas Bond allocation .
    pub verifas: AccountId,
    /// Milestone 2076 wallet .
    pub milestone: AccountId,
    /// Protocol Reserve wallet .
    pub reserve: AccountId,
    /// Faucet allocation .
    pub faucet: AccountId,
}

/// Apply the genesis state to an empty `StateDb`.
///
/// This writes accounts and time-lock contracts directly — no PoW, no
/// signatures, no parents. This is the one and only place in the protocol
/// where tokens are created. After this call, `TOTAL_SUPPLY_CHRONOS` is
/// distributed and no further minting is ever possible.
///
/// # Panics
/// Panics if the DB is not empty (genesis may only be applied once).
pub fn apply_genesis(db: &StateDb, params: &GenesisParams) -> Result<GenesisAccounts, ChronxError> {
    info!("applying ChronX genesis state");

    let accounts = build_accounts(params);

    // ── 1. Public sale allocation ────────────────────────────────────────────
    let mut public_sale_account = Account::new(
        accounts.public_sale.clone(),
        AuthPolicy::SingleSig {
            public_key: params.public_sale_key.clone(),
        },
    );
    public_sale_account.balance = PUBLIC_SALE_KX * CHRONOS_PER_KX;
    db.put_account(&public_sale_account)?;
    info!(
        account = %accounts.public_sale,
        balance = PUBLIC_SALE_KX,
        "genesis: public sale allocation"
    );

    // ── 2. Treasury time-locks (100 annual releases) ─────────────────────────
    let treasury_account = Account::new(
        accounts.treasury.clone(),
        AuthPolicy::SingleSig {
            public_key: params.treasury_key.clone(),
        },
    );
    db.put_account(&treasury_account)?;

    let schedule = treasury_release_schedule();
    for release in &schedule {
        let lock_id = treasury_lock_id(release.index);
        let contract = genesis_lock(
            lock_id.clone(),
            accounts.treasury.clone(),
            params.treasury_key.clone(),
            accounts.treasury.clone(),
            release.amount_chronos,
            release.unlock_at,
            Some(format!(
                "Treasury release #{} — year {}",
                release.index, release.year
            )),
        );
        db.put_timelock(&contract)?;
    }
    info!(
        releases = schedule.len(),
        total_kx = TREASURY_KX,
        "genesis: treasury time-locks created"
    );

    // ── 3. Node Rewards time-locks (100 annual releases) ─────────────────────
    let node_rewards_account = Account::new(
        accounts.node_rewards.clone(),
        AuthPolicy::SingleSig {
            public_key: params.node_rewards_key.clone(),
        },
    );
    db.put_account(&node_rewards_account)?;

    let nr_schedule = node_rewards_release_schedule();
    for release in &nr_schedule {
        let lock_id = node_rewards_lock_id(release.index);
        let contract = genesis_lock(
            lock_id.clone(),
            accounts.node_rewards.clone(),
            params.node_rewards_key.clone(),
            accounts.node_rewards.clone(),
            release.amount_chronos,
            release.unlock_at,
            Some(format!(
                "Node Rewards release #{} — year {}",
                release.index, release.year
            )),
        );
        db.put_timelock(&contract)?;
    }
    info!(
        releases = nr_schedule.len(),
        total_kx = NODE_REWARDS_KX,
        "genesis: node rewards time-locks created"
    );

    // ── 4. Humanity stake time-lock ──────────────────────────────────────────
    let humanity_account = Account::new(
        accounts.humanity.clone(),
        AuthPolicy::SingleSig {
            public_key: params.humanity_key.clone(),
        },
    );
    db.put_account(&humanity_account)?;

    let humanity_lock = genesis_lock(
        humanity_lock_id(),
        accounts.humanity.clone(),
        params.humanity_key.clone(),
        accounts.humanity.clone(),
        HUMANITY_STAKE_KX * CHRONOS_PER_KX,
        HUMANITY_UNLOCK_TIMESTAMP,
        Some(
            "The humanity stake — 1,000,000 KX — locked until Jan 1 2126 00:00:00 UTC. \
              100 years from genesis. The largest single promise in the ledger."
                .to_string(),
        ),
    );
    db.put_timelock(&humanity_lock)?;
    info!(
        unlock_year = 2126,
        kx = HUMANITY_STAKE_KX,
        "genesis: humanity stake time-lock created"
    );

    // ── 5. Milestone 2076 lock (separate wallet v8.0) ────────────────────────
    let milestone_account = Account::new(
        accounts.milestone.clone(),
        AuthPolicy::SingleSig {
            public_key: params.milestone_key.clone(),
        },
    );
    db.put_account(&milestone_account)?;

    let milestone_lock = genesis_lock(
        milestone_2076_lock_id(),
        accounts.milestone.clone(),
        params.milestone_key.clone(),
        accounts.milestone.clone(),
        MILESTONE_2076_KX * CHRONOS_PER_KX,
        MILESTONE_2076_UNLOCK_TIMESTAMP,
        Some(
            "ChronX 50-year milestone stake — locked at genesis, January 1 2026. \
              Unlocks at the halfway point to the Humanity Stake."
                .to_string(),
        ),
    );
    db.put_timelock(&milestone_lock)?;
    info!(
        unlock_year = 2076,
        kx = MILESTONE_2076_KX,
        "genesis: milestone 2076 time-lock created"
    );

    // ── 6. Protocol reserve lock (separate wallet v8.0) ──────────────────────
    let reserve_account = Account::new(
        accounts.reserve.clone(),
        AuthPolicy::SingleSig {
            public_key: params.reserve_key.clone(),
        },
    );
    db.put_account(&reserve_account)?;

    let reserve_lock = genesis_lock(
        protocol_reserve_lock_id(),
        accounts.reserve.clone(),
        params.reserve_key.clone(),
        accounts.reserve.clone(),
        PROTOCOL_RESERVE_KX * CHRONOS_PER_KX,
        PROTOCOL_RESERVE_UNLOCK_TIMESTAMP,
        Some(
            "ChronX protocol reserve — 10-year development fund. \
              Locked at genesis January 1 2026."
                .to_string(),
        ),
    );
    db.put_timelock(&reserve_lock)?;
    info!(
        unlock_year = 2036,
        kx = PROTOCOL_RESERVE_KX,
        "genesis: protocol reserve time-lock created"
    );

    // ── 7. Founder allocation  ──────────────────────────────────────────
    let mut founder_account = Account::new(
        accounts.founder.clone(),
        AuthPolicy::SingleSig {
            public_key: params.founder_key.clone(),
        },
    );
    founder_account.balance = FOUNDER_KX * CHRONOS_PER_KX;
    db.put_account(&founder_account)?;
    info!(
        account = %accounts.founder,
        balance_kx = FOUNDER_KX,
        "genesis: founder allocation"
    );

    // ── 8. MISAI Bond allocation  ─────────────────────────────────────
    let mut misai_account = Account::new(
        accounts.misai.clone(),
        AuthPolicy::SingleSig {
            public_key: params.misai_key.clone(),
        },
    );
    misai_account.balance = MISAI_BOND_KX * CHRONOS_PER_KX;
    db.put_account(&misai_account)?;
    info!(
        account = %accounts.misai,
        balance_kx = MISAI_BOND_KX,
        "genesis: MISAI bond allocation"
    );

    // ── 9. Verifas Bond allocation  ────────────────────────────────────
    let mut verifas_account = Account::new(
        accounts.verifas.clone(),
        AuthPolicy::SingleSig {
            public_key: params.verifas_key.clone(),
        },
    );
    verifas_account.balance = VERIFAS_BOND_KX * CHRONOS_PER_KX;
    db.put_account(&verifas_account)?;
    info!(
        account = %accounts.verifas,
        balance_kx = VERIFAS_BOND_KX,
        "genesis: Verifas bond allocation"
    );

    // ── 10. Faucet allocation  ─────────────────────────────────────
    let mut faucet_account = Account::new(
        accounts.faucet.clone(),
        AuthPolicy::SingleSig {
            public_key: params.faucet_key.clone(),
        },
    );
    faucet_account.balance = FAUCET_KX * CHRONOS_PER_KX;
    db.put_account(&faucet_account)?;
    info!(
        account = %accounts.faucet,
        balance_kx = FAUCET_KX,
        "genesis: faucet allocation"
    );

    // ── 11. Store axioms in genesis metadata  ─────────────────────────
    if let Some(ref axioms) = params.axioms {
        db.put_meta("genesis_axioms", axioms.as_bytes())?;
        info!("genesis: axioms stored in metadata ({} bytes)", axioms.len());
    }

    // ── Verify supply ────────────────────────────────────────────────────────
    verify_genesis_supply(db, params)?;

    db.flush()?;
    info!("genesis state committed to disk");

    Ok(accounts)
}

/// Verify that all genesis balances + pending time-locks sum correctly.
/// Only Public Sale + timelocked allocations are created at genesis.
/// Founder, Faucet, MISAI Bond, Verifas Bond are funded post-genesis from Public Sale.
/// Genesis block total = TOTAL_SUPPLY_CHRONOS (all KX starts in Public Sale + timelocks).
fn verify_genesis_supply(db: &StateDb, params: &GenesisParams) -> Result<(), ChronxError> {
    
    let bal = |key: &chronx_core::types::DilithiumPublicKey| -> Result<u128, ChronxError> {
        Ok(db
            .get_account(&chronx_crypto::hash::account_id_from_pubkey(&key.0))?
            .map(|a| a.balance)
            .unwrap_or(0))
    };

    let public_sale_bal = bal(&params.public_sale_key)?;
    let founder_bal = bal(&params.founder_key)?;
    let misai_bal = bal(&params.misai_key)?;
    let verifas_bal = bal(&params.verifas_key)?;
    let faucet_bal = bal(&params.faucet_key)?;

    let treasury_locks: u128 = treasury_release_schedule()
        .iter()
        .map(|r| r.amount_chronos)
        .sum();

    let node_rewards_locks: u128 = node_rewards_release_schedule()
        .iter()
        .map(|r| r.amount_chronos)
        .sum();

    let humanity_amount = HUMANITY_STAKE_KX * CHRONOS_PER_KX;
    let milestone_amount = MILESTONE_2076_KX * CHRONOS_PER_KX;
    let reserve_amount = PROTOCOL_RESERVE_KX * CHRONOS_PER_KX;

    let total = public_sale_bal
        + founder_bal
        + misai_bal
        + verifas_bal
        + faucet_bal
        + treasury_locks
        + node_rewards_locks
        + humanity_amount
        + milestone_amount
        + reserve_amount;

    // genesis block total = 8,095,000,000 KX (175M distributed post-genesis)
    let genesis_block_total: u128 = (PUBLIC_SALE_KX + TREASURY_KX + NODE_REWARDS_KX + HUMANITY_STAKE_KX + MILESTONE_2076_KX + PROTOCOL_RESERVE_KX) * CHRONOS_PER_KX;
    if total != genesis_block_total {
        return Err(ChronxError::GenesisSupplyMismatch {
            expected: genesis_block_total,
            got: total,
        });
    }

    info!(total_chronos = total, "genesis supply verified");
    Ok(())
}

/// Derive the genesis `AccountId`s from the public keys in `params`.
fn build_accounts(params: &GenesisParams) -> GenesisAccounts {
    use chronx_crypto::hash::account_id_from_pubkey;
    GenesisAccounts {
        public_sale: account_id_from_pubkey(&params.public_sale_key.0),
        treasury: account_id_from_pubkey(&params.treasury_key.0),
        node_rewards: account_id_from_pubkey(&params.node_rewards_key.0),
        humanity: account_id_from_pubkey(&params.humanity_key.0),
        founder: account_id_from_pubkey(&params.founder_key.0),
        misai: account_id_from_pubkey(&params.misai_key.0),
        verifas: account_id_from_pubkey(&params.verifas_key.0),
        milestone: account_id_from_pubkey(&params.milestone_key.0),
        reserve: account_id_from_pubkey(&params.reserve_key.0),
        faucet: account_id_from_pubkey(&params.faucet_key.0),
    }
}

/// Build a genesis-time `TimeLockContract` with V3 fields set to safe defaults.
fn genesis_lock(
    id: TxId,
    sender: AccountId,
    recipient_key: chronx_core::types::DilithiumPublicKey,
    recipient_account_id: AccountId,
    amount: u128,
    unlock_at: i64,
    memo: Option<String>,
) -> TimeLockContract {
    TimeLockContract {
        id,
        sender,
        recipient_key,
        recipient_account_id,
        amount,
        unlock_at,
        created_at: GENESIS_TIMESTAMP,
        status: TimeLockStatus::Pending,
        memo,
        lock_version: 0,
        claim_policy: None,
        beneficiary_anchor_commitment: None,
        org_identifier: None,
        cancellation_window_secs: None,
        notify_recipient: true,
        tags: None,
        private: false,
        expiry_policy: None,
        split_policy: None,
        claim_attempts_max: None,
        recurring: None,
        lock_marker: None,
        oracle_hint: None,
        jurisdiction_hint: None,
        governance_proposal_id: None,
        client_ref: None,
        transferable: false,
        transfer_policy: None,
        current_beneficiary: None,
        transfer_history: Vec::new(),
        earliest_transfer_date: None,
        email_recipient_hash: None,
        claim_window_secs: None,
        unclaimed_action: None,
        notification_sent: false,
        // ── V3.2 Conditional Payment fields ──────────────────────────────
        condition_description: None,
        condition_expiry: None,
        condition_oracle: None,
        condition_precision: None,
        condition_status: None,
        condition_attestation_id: None,
        condition_disputed: false,
        condition_dispute_window_secs: None,
        // ── V8 fields ───────────────────────────────────────────────────────
        lock_type: None,
        yield_opt_out: None,
        lock_metadata: None,
    }
}

/// Deterministic TxId for treasury release `k`: BLAKE3("treasury_release" || k LE u32).
pub fn treasury_lock_id(k: u32) -> TxId {
    let mut input = b"treasury_release".to_vec();
    input.extend_from_slice(&k.to_le_bytes());
    let hash = blake3::hash(&input);
    TxId::from_bytes(*hash.as_bytes())
}

/// Deterministic TxId for node rewards release `k`: BLAKE3("node_rewards_release" || k LE u32).
pub fn node_rewards_lock_id(k: u32) -> TxId {
    let mut input = b"node_rewards_release".to_vec();
    input.extend_from_slice(&k.to_le_bytes());
    let hash = blake3::hash(&input);
    TxId::from_bytes(*hash.as_bytes())
}

/// Deterministic TxId for the humanity stake lock.
pub fn humanity_lock_id() -> TxId {
    let hash = blake3::hash(b"humanity_stake_2126");
    TxId::from_bytes(*hash.as_bytes())
}

/// Deterministic TxId for the milestone 2076 lock.
pub fn milestone_2076_lock_id() -> TxId {
    let hash = blake3::hash(b"milestone_stake_2076");
    TxId::from_bytes(*hash.as_bytes())
}

/// Deterministic TxId for the protocol reserve lock.
pub fn protocol_reserve_lock_id() -> TxId {
    let hash = blake3::hash(b"protocol_reserve_2036");
    TxId::from_bytes(*hash.as_bytes())
}

/// Returns a dummy genesis `AccountId` (32 zero bytes) used as the
/// "null address" from which genesis tokens logically originate.
pub fn null_address() -> AccountId {
    AccountId::from_bytes([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use chronx_core::constants::{MILESTONE_2076_KX, PROTOCOL_RESERVE_KX};
    use chronx_crypto::KeyPair;

    fn test_params() -> GenesisParams {
        let ps = KeyPair::generate();
        let tr = KeyPair::generate();
        let hu = KeyPair::generate();
        let nr = KeyPair::generate();
        let fo = KeyPair::generate();
        let mi = KeyPair::generate();
        let ve = KeyPair::generate();
        let ms = KeyPair::generate();
        let re = KeyPair::generate();
        let fa = KeyPair::generate();
        GenesisParams {
            public_sale_key: ps.public_key.clone(),
            treasury_key: tr.public_key.clone(),
            humanity_key: hu.public_key.clone(),
            node_rewards_key: nr.public_key.clone(),
            founder_key: fo.public_key.clone(),
            misai_key: mi.public_key.clone(),
            verifas_key: ve.public_key.clone(),
            milestone_key: ms.public_key.clone(),
            reserve_key: re.public_key.clone(),
            faucet_key: fa.public_key.clone(),
            axioms: None,
        }
    }

    #[test]
    fn genesis_supply_is_exact() {
        use chronx_core::constants::{FAUCET_KX, FOUNDER_KX, MISAI_BOND_KX, VERIFAS_BOND_KX};

        let dir = std::env::temp_dir().join("chronx_genesis_test");
        let _ = std::fs::remove_dir_all(&dir);
        let db = StateDb::open(&dir).unwrap();
        let params = test_params();

        apply_genesis(&db, &params).expect("genesis must succeed");

        use chronx_crypto::hash::account_id_from_pubkey;
        let bal = |key: &chronx_core::types::DilithiumPublicKey| -> u128 {
            db.get_account(&account_id_from_pubkey(&key.0))
                .unwrap()
                .unwrap()
                .balance
        };

        let ps_bal = bal(&params.public_sale_key);
        let fo_bal = bal(&params.founder_key);
        let mi_bal = bal(&params.misai_key);
        let ve_bal = bal(&params.verifas_key);
        let fa_bal = bal(&params.faucet_key);

        let treasury_total: u128 = treasury_release_schedule()
            .iter()
            .map(|r| r.amount_chronos)
            .sum();
        let node_rewards_total: u128 = node_rewards_release_schedule()
            .iter()
            .map(|r| r.amount_chronos)
            .sum();
        let humanity = HUMANITY_STAKE_KX * CHRONOS_PER_KX;
        let milestone = MILESTONE_2076_KX * CHRONOS_PER_KX;
        let reserve = PROTOCOL_RESERVE_KX * CHRONOS_PER_KX;

        assert_eq!(
            ps_bal + fo_bal + mi_bal + ve_bal + fa_bal + treasury_total + node_rewards_total
                + humanity + milestone + reserve,
            TOTAL_SUPPLY_CHRONOS,
            "genesis total must equal TOTAL_SUPPLY_CHRONOS"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn treasury_lock_ids_are_unique() {
        let ids: Vec<_> = (1..=100).map(treasury_lock_id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 100);
    }

    #[test]
    fn node_rewards_lock_ids_are_unique() {
        let ids: Vec<_> = (1..=100).map(node_rewards_lock_id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(unique.len(), 100);
    }

    #[test]
    fn treasury_and_node_rewards_ids_dont_overlap() {
        let t_ids: std::collections::HashSet<_> = (1..=100).map(treasury_lock_id).collect();
        let n_ids: std::collections::HashSet<_> = (1..=100).map(node_rewards_lock_id).collect();
        assert!(
            t_ids.is_disjoint(&n_ids),
            "treasury and node rewards lock IDs must not overlap"
        );
    }
}
