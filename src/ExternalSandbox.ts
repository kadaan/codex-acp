import type {NetworkAccess, SandboxPolicy} from "./app-server/v2";

/**
 * Declares that the adapter is already confined by an outer sandbox, so Codex
 * must not apply one of its own.
 *
 * Codex sandboxes every command it runs. On macOS that is Seatbelt, and Seatbelt
 * cannot nest: `sandbox_apply` inside an already-sandboxed process fails EPERM,
 * so every command dies with
 * `sandbox-exec: sandbox_apply: Operation not permitted` (exit 71) before it
 * runs. Linux hits the same wall through bubblewrap/unshare in an unprivileged
 * container (#470). Any host that confines the adapter -- a supervising agent
 * runtime, a hardened container -- meets this, and today has no way out:
 *
 * - `sandbox_mode` in config.toml rejects the value (`unknown variant
 *   'external-sandbox', expected one of 'read-only', 'workspace-write',
 *   'danger-full-access'`), because the config key and the wire policy are
 *   different vocabularies.
 * - `thread/start` takes a `SandboxMode`, which has the same three values.
 * - OMITTING the per-turn policy does not help either: Codex falls back to the
 *   configured mode, which is still one that sandboxes.
 *
 * Only the per-turn `SandboxPolicy` can express it, and it already has the
 * variant. This is that switch.
 *
 * The value is the network posture the OUTER sandbox enforces, so Codex can
 * reason about reachability instead of assuming. It is not itself a boundary:
 * the outer sandbox is what actually permits or denies traffic, and a wrong
 * value here makes Codex's advice wrong, not the confinement weaker.
 *
 * Deliberately touches ONLY the sandbox axis. Approval policy is separate and is
 * left as the mode chose it, because a supervising host generally routes tool
 * calls through its own gate and needs Codex to keep asking. Reaching for
 * `agent-full-access` to escape the sandbox would silence approvals too -- and
 * per #470 it does not even work.
 */
export const EXTERNAL_SANDBOX_ENV = "CODEX_ACP_EXTERNAL_SANDBOX";

const NETWORK_ACCESS_VALUES = ["restricted", "enabled"] as const;

/**
 * Parse {@link EXTERNAL_SANDBOX_ENV}, returning null when it is unset.
 *
 * Throws on an unrecognized value rather than defaulting. A typo that quietly
 * meant "restricted" would hand back the pre-existing failure with no clue why
 * the switch appeared to do nothing, and this is exactly the class of setting
 * whose absence is invisible until a command fails.
 */
export function externalSandboxPolicy(
    env: NodeJS.ProcessEnv = process.env,
): SandboxPolicy | null {
    const raw = env[EXTERNAL_SANDBOX_ENV];
    if (raw === undefined || raw.trim() === "") {
        return null;
    }
    const networkAccess = raw.trim();
    if (!(NETWORK_ACCESS_VALUES as readonly string[]).includes(networkAccess)) {
        throw new Error(
            `${EXTERNAL_SANDBOX_ENV} must be one of ${NETWORK_ACCESS_VALUES.join(", ")}; got ${JSON.stringify(raw)}`,
        );
    }
    return {type: "externalSandbox", networkAccess: networkAccess as NetworkAccess};
}
