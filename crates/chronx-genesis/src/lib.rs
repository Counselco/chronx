//! chronx-genesis
//!
//! Builds the ChronX genesis state from scratch, writing directly into a
//! `StateDb` without going through the normal transaction engine (genesis
//! transactions have no parents and no PoW — they are the founding document).
//!
//! Genesis allocations (all at GENESIS_TIMESTAMP = 2026-12-31 23:59:59 UTC):
//!   1. Public sale address  — 7,269,000,000 KX  (spendable immediately)
//!   2. Treasury             — 1,000,000,000 KX  (100 annual time-locks, log-declining)
//!   3. Humanity stake       — 1,000,000 KX       (single lock until 2127-01-01)

pub mod params;

pub use params::GenesisParams;

use chronx_core::account::{Account, AuthPolicy, TimeLockContract, TimeLockStatus};
use chronx_core::constants::{
    GENESIS_TIMESTAMP, HUMANITY_STAKE_KX, HUMANITY_UNLOCK_TIMESTAMP, PUBLIC_SALE_KX,
    TREASURY_KX, CHRONOS_PER_KX,
};
use chronx_core::error::ChronxError;
use chronx_core::types::{AccountId, TxId};
use chronx_state::StateDb;
use chronx_timelock::treasury_release_schedule;
use tracing::info;

/// Seed accounts used in genesis. All public keys are zero-filled placeholders;
/// real deployments would supply actual keys via `GenesisParams`.
pub struct GenesisAccounts {
    /// Receives the public sale allocation. Real key supplied at launch.
    pub public_sale: AccountId,
    /// Holds the 100-year treasury time-locks. Governance-controlled.
    pub treasury: AccountId,
    /// The humanity stake recipient. Long-horizon public key.
    pub humanity: AccountId,
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
        // Each release is a separate time-lock contract keyed by a
        // deterministic ID: BLAKE3(b"treasury" || k as u32 LE bytes).
        let lock_id = treasury_lock_id(release.index);

        let contract = TimeLockContract {
            id: lock_id.clone(),
            sender: accounts.treasury.clone(),
            recipient_key: params.treasury_key.clone(),
            recipient_account_id: accounts.treasury.clone(),
            amount: release.amount_chronos,
            unlock_at: release.unlock_at,
            created_at: GENESIS_TIMESTAMP,
            status: TimeLockStatus::Pending,
            memo: Some(format!(
                "Treasury release #{} — year {}",
                release.index, release.year
            )),
        };
        db.put_timelock(&contract)?;
    }
    info!(
        releases = schedule.len(),
        total_kx = TREASURY_KX,
        "genesis: treasury time-locks created"
    );

    // ── 3. Humanity stake time-lock ──────────────────────────────────────────
    let humanity_account = Account::new(
        accounts.humanity.clone(),
        AuthPolicy::SingleSig {
            public_key: params.humanity_key.clone(),
        },
    );
    db.put_account(&humanity_account)?;

    let humanity_lock = TimeLockContract {
        id: humanity_lock_id(),
        sender: accounts.humanity.clone(),
        recipient_key: params.humanity_key.clone(),
        recipient_account_id: accounts.humanity.clone(),
        amount: HUMANITY_STAKE_KX * CHRONOS_PER_KX,
        unlock_at: HUMANITY_UNLOCK_TIMESTAMP,
        created_at: GENESIS_TIMESTAMP,
        status: TimeLockStatus::Pending,
        memo: Some(
            "The humanity stake — 1,000,000 KX — locked until Jan 1 2127 00:00:00 UTC. \
             The largest single promise in the ledger."
                .to_string(),
        ),
    };
    db.put_timelock(&humanity_lock)?;
    info!(
        unlock_year = 2127,
        kx = HUMANITY_STAKE_KX,
        "genesis: humanity stake time-lock created"
    );

    // ── Verify supply ────────────────────────────────────────────────────────
    verify_genesis_supply(db, params)?;

    db.flush()?;
    info!("genesis state committed to disk");

    Ok(accounts)
}

/// Verify that all balances + pending time-locks sum to exactly TOTAL_SUPPLY.
fn verify_genesis_supply(db: &StateDb, params: &GenesisParams) -> Result<(), ChronxError> {
    use chronx_core::constants::TOTAL_SUPPLY_CHRONOS;

    let public_sale_bal = db
        .get_account(&chronx_crypto::hash::account_id_from_pubkey(&params.public_sale_key.0))?
        .map(|a| a.balance)
        .unwrap_or(0);

    let treasury_locks: u128 = treasury_release_schedule()
        .iter()
        .map(|r| r.amount_chronos)
        .sum();

    let humanity_amount = HUMANITY_STAKE_KX * CHRONOS_PER_KX;

    let total = public_sale_bal + treasury_locks + humanity_amount;

    if total != TOTAL_SUPPLY_CHRONOS {
        return Err(ChronxError::GenesisSupplyMismatch {
            expected: TOTAL_SUPPLY_CHRONOS,
            got: total,
        });
    }

    info!(total_chronos = total, "genesis supply verified");
    Ok(())
}

fn build_accounts(params: &GenesisParams) -> GenesisAccounts {
    use chronx_crypto::hash::account_id_from_pubkey;
    GenesisAccounts {
        public_sale: account_id_from_pubkey(&params.public_sale_key.0),
        treasury: account_id_from_pubkey(&params.treasury_key.0),
        humanity: account_id_from_pubkey(&params.humanity_key.0),
    }
}

/// Deterministic TxId for treasury release `k`: BLAKE3("treasury_release" || k LE u32).
pub fn treasury_lock_id(k: u32) -> TxId {
    let mut input = b"treasury_release".to_vec();
    input.extend_from_slice(&k.to_le_bytes());
    let hash = blake3::hash(&input);
    TxId::from_bytes(*hash.as_bytes())
}

/// Deterministic TxId for the humanity stake lock.
pub fn humanity_lock_id() -> TxId {
    let hash = blake3::hash(b"humanity_stake_2127");
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
    use chronx_core::constants::TOTAL_SUPPLY_CHRONOS;
    use chronx_crypto::KeyPair;

    fn test_params() -> GenesisParams {
        let ps = KeyPair::generate();
        let tr = KeyPair::generate();
        let hu = KeyPair::generate();
        GenesisParams {
            public_sale_key: ps.public_key.clone(),
            treasury_key: tr.public_key.clone(),
            humanity_key: hu.public_key.clone(),
        }
    }

    #[test]
    fn genesis_supply_is_exact() {
        let dir = std::env::temp_dir().join("chronx_genesis_test");
        let _ = std::fs::remove_dir_all(&dir);
        let db = StateDb::open(&dir).unwrap();
        let params = test_params();

        apply_genesis(&db, &params).expect("genesis must succeed");

        // Public sale balance
        use chronx_crypto::hash::account_id_from_pubkey;
        let ps_id = account_id_from_pubkey(&params.public_sale_key.0);
        let ps_bal = db.get_account(&ps_id).unwrap().unwrap().balance;

        let treasury_total: u128 = treasury_release_schedule()
            .iter()
            .map(|r| r.amount_chronos)
            .sum();
        let humanity = HUMANITY_STAKE_KX * CHRONOS_PER_KX;

        assert_eq!(
            ps_bal + treasury_total + humanity,
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
}
