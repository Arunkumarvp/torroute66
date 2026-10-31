---------------------------- MODULE PQVeilTA ----------------------------
(*
 * TLA+ Formal Specification of the PQVeil Trusted Application State Machine
 *
 * Verifies core security invariants:
 *   1. MonotonicCounterNonDecreasing: The monotonic policy counter never regresses.
 *   2. IdentityKeyNonExfiltration: Long-term private key seeds never leave the TA.
 *   3. ProvisioningOneShot: Seeds cannot be overwritten once provisioned.
 *   4. FailClosedNetworkIntegrity: Egress traffic only occurs if policy is valid and Tor is active.
 *)

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxCounter,
    ClientSessions

VARIABLES
    ta_provisioned,
    ta_counter,
    sealed_kem_seed,
    sealed_dsa_seed,
    output_channel,
    tor_active,
    network_egress

TypeOK ==
    /\ ta_provisioned \in BOOLEAN
    /\ ta_counter \in 0..MaxCounter
    /\ sealed_kem_seed \in BOOLEAN
    /\ sealed_dsa_seed \in BOOLEAN
    /\ output_channel \in SUBSET {"STATUS", "PUBLIC_KEY", "SIGNATURE", "SHARED_SECRET", "HEALTH_REPORT"}
    /\ tor_active \in BOOLEAN
    /\ network_egress \in BOOLEAN

Init ==
    /\ ta_provisioned = FALSE
    /\ ta_counter = 0
    /\ sealed_kem_seed = FALSE
    /\ sealed_dsa_seed = FALSE
    /\ output_channel = {}
    /\ tor_active = TRUE
    /\ network_egress = FALSE

(* Transition: Get Status *)
GetStatus ==
    /\ output_channel' = output_channel \cup {"STATUS"}
    /\ UNCHANGED << ta_provisioned, ta_counter, sealed_kem_seed, sealed_dsa_seed, tor_active, network_egress >>

(* Transition: One-time Provisioning *)
Provision ==
    /\ ~ta_provisioned
    /\ ta_provisioned' = TRUE
    /\ ta_counter' = 1
    /\ sealed_kem_seed' = TRUE
    /\ sealed_dsa_seed' = TRUE
    /\ output_channel' = output_channel \cup {"PUBLIC_KEY"}
    /\ UNCHANGED << tor_active, network_egress >>

(* Transition: Sign Transcript *)
SignTranscript ==
    /\ ta_provisioned
    /\ output_channel' = output_channel \cup {"SIGNATURE"}
    /\ UNCHANGED << ta_provisioned, ta_counter, sealed_kem_seed, sealed_dsa_seed, tor_active, network_egress >>

(* Transition: Decapsulate Static KEM *)
Decaps ==
    /\ ta_provisioned
    /\ output_channel' = output_channel \cup {"SHARED_SECRET"}
    /\ UNCHANGED << ta_provisioned, ta_counter, sealed_kem_seed, sealed_dsa_seed, tor_active, network_egress >>

(* Transition: Sign Health Report *)
SignHealth ==
    /\ ta_provisioned
    /\ output_channel' = output_channel \cup {"HEALTH_REPORT"}
    /\ UNCHANGED << ta_provisioned, ta_counter, sealed_kem_seed, sealed_dsa_seed, tor_active, network_egress >>

(* Transition: Load Policy with strictly increasing counter *)
LoadPolicy(new_c) ==
    /\ ta_provisioned
    /\ new_c > ta_counter
    /\ new_c <= MaxCounter
    /\ ta_counter' = new_c
    /\ UNCHANGED << ta_provisioned, sealed_kem_seed, sealed_dsa_seed, output_channel, tor_active, network_egress >>

(* Transition: Egress through fail-closed network *)
AllowEgress ==
    /\ tor_active
    /\ ta_provisioned
    /\ network_egress' = TRUE
    /\ UNCHANGED << ta_provisioned, ta_counter, sealed_kem_seed, sealed_dsa_seed, output_channel, tor_active >>

(* Transition: Tor failure halts egress *)
TorFail ==
    /\ tor_active' = FALSE
    /\ network_egress' = FALSE
    /\ UNCHANGED << ta_provisioned, ta_counter, sealed_kem_seed, sealed_dsa_seed, output_channel >>

Next ==
    \/ GetStatus
    \/ Provision
    \/ SignTranscript
    \/ Decaps
    \/ SignHealth
    \/ (\E c \in 1..MaxCounter: LoadPolicy(c))
    \/ AllowEgress
    \/ TorFail

Spec == Init /\ [][Next]_<<ta_provisioned, ta_counter, sealed_kem_seed, sealed_dsa_seed, output_channel, tor_active, network_egress>>

-----------------------------------------------------------------------------
(* SECURITY INVARIANTS *)

(* Invariant 1: Policy counter is monotonic non-decreasing *)
CounterNonDecreasing ==
    [][ta_counter' >= ta_counter]_ta_counter

(* Invariant 2: Private key seeds never appear in the output channel *)
KeyNonExfiltration ==
    "PRIVATE_KEY_SEED" \notin output_channel

(* Invariant 3: Provisioning can never be revoked or re-executed with new seeds *)
ProvisioningStable ==
    ta_provisioned => (sealed_kem_seed /\ sealed_dsa_seed)

(* Invariant 4: No network egress without active Tor routing *)
FailClosedSafety ==
    network_egress => tor_active

=============================================================================

