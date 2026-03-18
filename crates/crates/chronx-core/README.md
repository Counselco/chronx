# chronx-core

Core type definitions and data structures for the ChronX protocol. Every other crate in the workspace depends on this one.

Defines the canonical on-chain types: `Account` (balance, authentication policy, recovery state), `TimeLockContract` (the on-chain promise primitive), `Transaction` and `Action` (the unit of change submitted to the network), `AuthPolicy` (SingleSig / MultiSig / RecoveryEnabled), and the full set of supporting enums (`TimeLockStatus`, `ExpiryPolicy`, `RecurringPolicy`, `UnclaimedAction`). All V2, V3, and V3.1 extensibility fields use `#[serde(default)]` so that records written by older nodes deserialise correctly without migration.
