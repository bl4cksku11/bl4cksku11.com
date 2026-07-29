# CVE-2026-55658: El buffer del streaming escrow de Gardens v2 se drena al beneficiario del proposal en cancel vía el claim() sin permisos

**Publicado:** 2026-07-28 **Reportado:** 2026-06-09 **Severidad:** 7.3 Alta **Estado:** CVE-2026-55658 / GHSA-jwvq-5xmf-f377 asignados (publicado 2026-06-14) **CWEs:** CWE-840 (Business Logic Errors) + CWE-862 (Missing Authorization)

---

Cuando un streaming proposal de Gardens v2 se fondea, el cluster de contratos de streaming mueve fondos reales del pool al `StreamingEscrow` del proposal para respaldar el constant flow agreement de Superfluid (el deposit del CFA, más un 0.5% de margen). `cancelProposal` después pone en cero las member units del GDA del escrow pero nunca recupera ese balance parqueado. El `claim()` sin permisos forwardea el balance entero del escrow, incluyendo el buffer fondeado por el pool, al beneficiario. El beneficiario lo elige quien submitea el proposal y por default es el propio submitter. El único path que devuelve fondos del escrow al pool es `drainToStrategy`, que es `onlyStrategy` y solo se alcanza desde el ruling de dispute-reject, nunca desde cancel ni desde el fin natural del stream.

Un member de la community con derechos de submitear proposals convierte el loop rutinario "submit, cancel, claim" en un drain repetible de los fondos del pool.

---

## El bug

`CVStreamingFacet._topUpEscrowDepositIfNeeded` transfiere SuperTokens del pool desde la strategy al escrow (`pkg/contracts/src/CVStrategy/facets/CVStreamingFacet.sol:373`):

```solidity
uint256 topUp = missingDeposit > strategyBalance ? strategyBalance : missingDeposit;
if (topUp != 0) {
    if (!superfluidToken.transfer(escrow, topUp)) {
        revert SuperTokenTransferFailed(escrow, topUp);
    }
    return true;
}
```

`cancelProposal` pone en cero las member units del GDA del escrow y refunde el collateral del submitter, pero no emite ningún `drainToStrategy` (`pkg/contracts/src/CVStrategy/facets/CVProposalFacet.sol:154`):

```solidity
if (proposalType == ProposalType.Streaming) {
    address escrow = streamingEscrow(proposalId);
    address member = escrow == address(0) ? proposals[proposalId].beneficiary : escrow;
    if (!superfluidGDA.updateMemberUnits(member, 0)) {
        revert UpdateMemberUnitsFailed(member, 0);
    }
}
```

Con las member units en cero, `_currentGDAFlowRate()` devuelve cero, así que `depositAmount()` devuelve cero y el floor de deposit reservado colapsa (`pkg/contracts/src/CVStrategy/StreamingEscrow.sol:225`):

```solidity
function depositAmount() public view returns (uint256) {
    int96 flowRate = _currentGDAFlowRate();
    if (flowRate <= 0) {
        return 0;            // post-cancel: member flow is 0
    }
    ...
}
```

`claim()` es sin permisos y forwardea `balance - depositAmount()`, ahora el balance entero, al beneficiario (`pkg/contracts/src/CVStrategy/StreamingEscrow.sol:218`):

```solidity
function claim() external {
    if (disputed) {
        revert Disputed();
    }
    _drainExcessToBeneficiary();   // manda balance - 0 al beneficiario
}
```

La cadena de decisiones cada una aisladamente parece razonable. El top-up del buffer es correcto (Superfluid necesita el deposit mientras streamea). Poner en cero las member units en cancel es correcto (el streaming terminó). Hacer `claim()` sin permisos es cómodo (cualquiera puede triggerar un drain owed al beneficiario del excess). Solo la interacción entre ellas crea el drain: cancel remueve la reserva, `claim()` lee una reserva en cero y manda todo lo que el escrow tiene.

## Dónde debería vivir el fix

El único path que devuelve fondos del escrow al pool es `drainToStrategy`, y su único caller hoy es dispute-reject en `CVDisputeFacet.sol:205`. Cancel y natural completion no lo alcanzan. El gap es un paso faltante de "devolver el buffer al pool" en cualquier evento de lifecycle que termina el stream.

## Proof of Concept

Test de fork de Foundry contra la CVStrategy live de Gardens `0x2B1915a2e0293B3a434df58b921d8f7e320da077` en Optimism al block 150386758. El test hace prank de la strategy live para que los SuperTokens que fondean el escrow sean los fondos reales del pool del protocolo, exactamente el path que toma `_topUpEscrowDepositIfNeeded`. El escrow queda en el estado post-cancel (member units del GDA en cero, no disputado), así que `depositAmount()` devuelve cero y un `claim()` del beneficiario drena el buffer completo. Nada se broadcastea on-chain y no se usa ninguna key.

```
$ RPC_URL_OPT=https://mainnet.optimism.io \
  forge test --match-path pkg/contracts/test/fork/PoC_F1_EscrowBufferLeakFork.t.sol -vv

[PASS] test_PoC_cancelled_escrow_buffer_drains_to_attacker_beneficiary()
  pool funds parked as buffer:        5000000000000000000   (5 GARDENx)
  drained to attacker via claim():    5000000000000000000   (entire buffer)
  escrow balance after claim:         0
```

El hecho load-bearing confirmado en el fork: en Superfluid real, `depositAmount()` devuelve cero para un escrow con flow en cero en vez de revertir, así que `claim()` tiene éxito y forwardea el balance entero al beneficiario.

Pasos de reproducción en producción:

1. Como member de la community, submitear un streaming proposal. El submitter es el beneficiario por default, o setea el beneficiario a una dirección controlada dentro del edit window.
2. Adquirir conviction suficiente para que el proposal pase `_isProposalAboveThreshold` (self-staking alcanza). Un keeper autorizado llama `rebalance()`, que corre `_topUpEscrowDepositIfNeeded` y mueve SuperTokens del pool al escrow.
3. Llamar `cancelProposal`. Las units van a cero, el collateral del submitter se refunde, y el escrow se queda con el buffer.
4. Llamar `claim()` en el escrow. El buffer completo, incluyendo la porción fondeada por el pool, se transfiere al beneficiario. Repetir desde el paso 1.

## Impacto

Un member de la community que submitea un streaming proposal hace que el pool fondee el buffer del escrow, después en cancel se lleva ese buffer al beneficiario encima de cualquier monto legítimamente streameado, y los fondos nunca vuelven al pool. El test de fork mueve 5 GARDENx de fondos reales del pool desde la strategy al beneficiario en un solo `claim()`. El buffer escala con el share de conviction del proposal sobre el streaming rate, así que un proposal con más conviction rinde más por ciclo, y la secuencia create-fund-cancel-claim se repite. Un lifecycle rutinario de proposal se vuelve un drain repetible de fondos del pool.

Environments afectados: pools de CVStrategy de Gardens v2 con streaming GDA de Superfluid habilitado, en Optimism, Gnosis Chain, Polygon, Arbitrum, Base y Celo.

**CVSS 3.1:** 7.3 Alta, `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N`. El `PR:L` refleja que el caller tiene que ser un member de la community que pueda submitear un streaming proposal. El buffer solo se fondea después de que un keeper autorizado corre `rebalance()` mientras el proposal está sobre threshold; los keepers corren en schedule, así que es una condición normal de operación, no un privilegio que el caller tenga que tener.

## Fix sugerido

Dos direcciones ortogonales, cualquiera o las dos:

1. **Reclaim en cada path que termina el stream.** En `cancelProposal`, en el path de natural completion, y adentro de `stopEscrowStream`, llamar `escrow.drainToStrategy()` para devolver el balance residual del escrow al pool antes o después de poner las units en cero. Espeja lo que `CVDisputeFacet.sol:205` ya hace en dispute-reject.

2. **Gate `claim()` para que no pueda routear el residuo post-cancel al beneficiario.** Por ejemplo: restringir a `onlyStrategyOrOwner`, o mantener un floor de deposit reservado no-cero mientras el escrow todavía tiene buffer protocol-owned.

## Divulgación

Reportado privadamente a 1Hive vía el private vulnerability reporting de GitHub el 2026-06-09 contra `main` HEAD `3e595f3`. CVE-2026-55658 asignado, GHSA-jwvq-5xmf-f377 publicado el 2026-06-14.

Gracias al equipo de 1Hive por el triage rápido.

## Links

- Advisory: https://github.com/1Hive/gardens-v2/security/advisories/GHSA-jwvq-5xmf-f377
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-55658
- 1Hive Gardens v2: https://github.com/1Hive/gardens-v2
- Docs de Superfluid GDA: https://docs.superfluid.finance/docs/protocol/distributions/overview
- CWE-840: https://cwe.mitre.org/data/definitions/840.html
- CWE-862: https://cwe.mitre.org/data/definitions/862.html
