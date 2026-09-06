import {describe, expect, it} from "vitest";
import {EXTERNAL_SANDBOX_ENV, externalSandboxPolicy} from "../ExternalSandbox";

describe("externalSandboxPolicy", () => {
    it("is off unless the host asks for it", () => {
        expect(externalSandboxPolicy({})).toBeNull();
    });

    it("treats an empty or blank value as unset", () => {
        // A launcher that exports the variable unconditionally and fills it
        // conditionally would otherwise hand every ordinary user a policy they
        // never asked for.
        expect(externalSandboxPolicy({[EXTERNAL_SANDBOX_ENV]: ""})).toBeNull();
        expect(externalSandboxPolicy({[EXTERNAL_SANDBOX_ENV]: "   "})).toBeNull();
    });

    it.each(["restricted", "enabled"] as const)(
        "carries the outer sandbox's network posture: %s",
        (networkAccess) => {
            expect(externalSandboxPolicy({[EXTERNAL_SANDBOX_ENV]: networkAccess}))
                .toEqual({type: "externalSandbox", networkAccess});
        },
    );

    it("tolerates surrounding whitespace", () => {
        expect(externalSandboxPolicy({[EXTERNAL_SANDBOX_ENV]: " enabled "}))
            .toEqual({type: "externalSandbox", networkAccess: "enabled"});
    });

    it("throws on an unrecognized value rather than defaulting", () => {
        // Defaulting is the dangerous option: the failure this switch exists to
        // prevent is a command dying with a sandbox error, so a typo that
        // silently meant "off" reproduces exactly that with no clue why the
        // setting appeared to do nothing.
        expect(() => externalSandboxPolicy({[EXTERNAL_SANDBOX_ENV]: "true"}))
            .toThrow(/must be one of restricted, enabled/);
    });
});
