---- MODULE AutomationControlPlane ----
EXTENDS Naturals, TLC

CONSTANT MaxStale

ASSUME MaxStale \in Nat /\ MaxStale > 0

(*
--algorithm ControlPlane
variables
  phase = "idle",
  lease = FALSE,
  fresh = TRUE,
  checks = TRUE,
  authorized = FALSE,
  cancelled = FALSE,
  mutated = FALSE,
  merged = FALSE,
  mutationProof = FALSE,
  mergeProof = FALSE,
  stale = MaxStale,
  previousStale = MaxStale;

begin
ControlLoop:
  while TRUE do
    either
Plan:
      if phase = "idle" /\ ~cancelled then
        phase := "planned";
      end if;
    or
AcquireLease:
      if phase = "planned" /\ ~cancelled then
        lease := TRUE;
        phase := "leased";
      end if;
    or
Approve:
      if phase = "leased" /\ lease /\ fresh /\ checks /\ ~cancelled then
        authorized := TRUE;
        phase := "approved";
      end if;
    or
Mutate:
      if phase = "approved" /\ lease /\ authorized /\ fresh /\ checks /\ ~cancelled then
        mutationProof := lease /\ authorized /\ fresh /\ checks /\ ~cancelled;
        mutated := TRUE;
        phase := "mutated";
      end if;
    or
Merge:
      if phase = "mutated" /\ lease /\ authorized /\ fresh /\ checks /\ ~cancelled then
        mergeProof := lease /\ authorized /\ fresh /\ checks /\ ~cancelled;
        merged := TRUE;
        phase := "completed";
      end if;
    or
ExpireLease:
      lease := FALSE;
    or
StaleCandidate:
      if ~merged then
        fresh := FALSE;
      end if;
    or
InvalidateChecks:
      if ~merged then
        checks := FALSE;
      end if;
    or
Cancel:
      if ~merged then
        cancelled := TRUE;
      end if;
    or
CleanupOne:
      if stale > 0 then
        previousStale := stale;
        stale := stale - 1;
      end if;
    end either;
  end while;

end algorithm;
*)

\* BEGIN TRANSLATION
\* END TRANSLATION

Phases == {"idle", "planned", "leased", "approved", "mutated", "completed"}

TypeInvariant ==
  /\ phase \in Phases
  /\ lease \in BOOLEAN
  /\ fresh \in BOOLEAN
  /\ checks \in BOOLEAN
  /\ authorized \in BOOLEAN
  /\ cancelled \in BOOLEAN
  /\ mutated \in BOOLEAN
  /\ merged \in BOOLEAN
  /\ mutationProof \in BOOLEAN
  /\ mergeProof \in BOOLEAN
  /\ stale \in 0..MaxStale
  /\ previousStale \in 0..MaxStale

MutationRequiresProof == ~mutated \/ mutationProof

MergeRequiresProof == ~merged \/ (mutated /\ mergeProof)

CancellationStopsMerge == ~cancelled \/ ~merged

CleanupMonotone == stale <= previousStale

CompletedIsMerged == (phase = "completed") => merged

NegativeControl == ~merged

====
