# CVE-2026-55658: Gardens v2 streaming escrow buffer drains to the proposal beneficiary on cancel via permissionless claim()

**Published:** 2026-07-28 **Reported:** 2026-06-09 **Severity:** 7.3 High **Status:** Assigned CVE-2026-55658 / GHSA-jwvq-5xmf-f377 (published 2026-06-14) **CWEs:** CWE-840 (Business Logic Errors) + CWE-862 (Missing Authorization)

---

When a Gardens v2 streaming proposal is funded, the cluster of streaming contracts moves real pool funds into the proposal's `StreamingEscrow` to back the Superfluid constant flow agreement (the CFA deposit, plus a 0.5% margin). `cancelProposal` then zeroes the escrow's GDA member units but never reclaims that parked balance. The permissionless `claim()` forwards the escrow's entire balance, including the pool-funded buffer, to the beneficiary. The beneficiary is chosen by the proposal submitter and defaults to the submitter. The only path that returns escrow funds to the pool is `drainToStrategy`, which is `onlyStrategy` and is reached solely from the dispute reject ruling, never from cancel or natural completion.

A community member with proposal-submission rights turns a routine "submit, cancel, claim" loop into a repeatable drain of pool funds.

---

## The bug

`CVStreamingFacet._topUpEscrowDepositIfNeeded` transfers pool SuperTokens from the strategy into the escrow (`pkg/contracts/src/CVStrategy/facets/CVStreamingFacet.sol:373`):

```solidity
uint256 topUp = missingDeposit > strategyBalance ? strategyBalance : missingDeposit;
if (topUp != 0) {
    if (!superfluidToken.transfer(escrow, topUp)) {
        revert SuperTokenTransferFailed(escrow, topUp);
    }
    return true;
}
```

`cancelProposal` zeroes the escrow's GDA member units and refunds the submitter collateral, but issues no `drainToStrategy` (`pkg/contracts/src/CVStrategy/facets/CVProposalFacet.sol:154`):

```solidity
if (proposalType == ProposalType.Streaming) {
    address escrow = streamingEscrow(proposalId);
    address member = escrow == address(0) ? proposals[proposalId].beneficiary : escrow;
    if (!superfluidGDA.updateMemberUnits(member, 0)) {
        revert UpdateMemberUnitsFailed(member, 0);
    }
}
```

With member units at zero, `_currentGDAFlowRate()` returns zero, so `depositAmount()` returns zero and the reserved deposit floor collapses (`pkg/contracts/src/CVStrategy/StreamingEscrow.sol:225`):

```solidity
function depositAmount() public view returns (uint256) {
    int96 flowRate = _currentGDAFlowRate();
    if (flowRate <= 0) {
        return 0;            // post-cancel: member flow is 0
    }
    ...
}
```

`claim()` is permissionless and forwards `balance - depositAmount()`, now the entire balance, to the beneficiary (`pkg/contracts/src/CVStrategy/StreamingEscrow.sol:218`):

```solidity
function claim() external {
    if (disputed) {
        revert Disputed();
    }
    _drainExcessToBeneficiary();   // sends balance - 0 to beneficiary
}
```

The chain of decisions each looks reasonable in isolation. The buffer top-up is correct (Superfluid needs the deposit while streaming). Zeroing member units on cancel is correct (streaming is over). Making `claim()` permissionless is convenient (anyone can trigger a beneficiary-owed drain of excess). Only the interaction between them creates the drain: cancel removes the reservation, `claim()` reads a zero reservation and sends everything the escrow holds.

## Where the fix should live

The only path that returns escrow funds to the pool is `drainToStrategy`, and its only caller today is dispute-reject in `CVDisputeFacet.sol:205`. Cancel and natural completion do not reach it. The gap is a missing "return the buffer to the pool" step on any lifecycle event that terminates the stream.

## Proof of Concept

Foundry fork test against the live Gardens CVStrategy `0x2B1915a2e0293B3a434df58b921d8f7e320da077` on Optimism at block 150386758. The test pranks the live strategy so the SuperTokens that fund the escrow are the protocol's real pool funds, exactly the path `_topUpEscrowDepositIfNeeded` takes. The escrow sits in the post-cancel state (zero GDA member units, not disputed), so `depositAmount()` returns zero and a `claim()` from the beneficiary drains the full buffer. Nothing is broadcast on chain and no key is used.

```
$ RPC_URL_OPT=https://mainnet.optimism.io \
  forge test --match-path pkg/contracts/test/fork/PoC_F1_EscrowBufferLeakFork.t.sol -vv

[PASS] test_PoC_cancelled_escrow_buffer_drains_to_attacker_beneficiary()
  pool funds parked as buffer:        5000000000000000000   (5 GARDENx)
  drained to attacker via claim():    5000000000000000000   (entire buffer)
  escrow balance after claim:         0
```

The load-bearing fact confirmed on the fork: on real Superfluid, `depositAmount()` returns zero for a zero-flow escrow instead of reverting, so `claim()` succeeds and forwards the whole balance to the beneficiary.

Reproduction steps in production:

1. As a community member, submit a streaming proposal. The submitter is the default beneficiary, or sets the beneficiary to a controlled address within the edit window.
2. Acquire enough conviction for the proposal to clear `_isProposalAboveThreshold` (self-staking suffices). An authorized keeper calls `rebalance()`, which runs `_topUpEscrowDepositIfNeeded` and moves pool SuperTokens into the escrow.
3. Call `cancelProposal`. Units go to zero, the submitter collateral is refunded, and the escrow keeps the buffer.
4. Call `claim()` on the escrow. The full buffer, including the pool-funded portion, transfers to the beneficiary. Repeat from step 1.

## Impact

A community member who submits a streaming proposal makes the pool fund the escrow buffer, then on cancel takes that buffer to the beneficiary on top of any legitimately streamed amount, and the funds never return to the pool. The fork test moves 5 GARDENx of real pool funds from the strategy to the beneficiary in a single `claim()`. The buffer scales with the proposal's conviction share of the streaming rate, so a higher-conviction proposal yields more per cycle, and the create-fund-cancel-claim sequence repeats. A routine proposal lifecycle becomes a repeatable drain of pool funds.

Affected environments: Gardens v2 CVStrategy pools with Superfluid GDA streaming enabled, on Optimism, Gnosis Chain, Polygon, Arbitrum, Base, and Celo.

**CVSS 3.1:** 7.3 High, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N`. `PR:L` reflects that the caller must be a community member who can submit a streaming proposal. The buffer is funded only after an authorized keeper runs `rebalance()` while the proposal is above threshold; keepers run it on a schedule, so this is a normal operating condition, not a privilege the caller must hold.

## Suggested fix

Two orthogonal directions, either or both:

1. **Reclaim on every stream-ending path.** In `cancelProposal`, in the natural completion path, and inside `stopEscrowStream`, call `escrow.drainToStrategy()` to return the residual escrow balance to the pool before or after zeroing units. Mirrors what `CVDisputeFacet.sol:205` already does on dispute-reject.

2. **Gate `claim()` so it cannot route post-cancel residue to the beneficiary.** For example: restrict to `onlyStrategyOrOwner`, or keep a nonzero reserved-deposit floor while the escrow still holds protocol-owned buffer.

## Disclosure

Reported privately to 1Hive via GitHub's private vulnerability reporting on 2026-06-09 against `main` HEAD `3e595f3`. CVE-2026-55658 assigned, GHSA-jwvq-5xmf-f377 published 2026-06-14.

Thanks to the 1Hive team for the fast triage.

## Links

- Advisory: https://github.com/1Hive/gardens-v2/security/advisories/GHSA-jwvq-5xmf-f377
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-55658
- 1Hive Gardens v2: https://github.com/1Hive/gardens-v2
- Superfluid GDA docs: https://docs.superfluid.finance/docs/protocol/distributions/overview
- CWE-840: https://cwe.mitre.org/data/definitions/840.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
