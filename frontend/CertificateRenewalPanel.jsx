/**
 * CertificateRenewalPanel — opt-in automated renewal UI for one certificate.
 *
 * Drop into the certificate row expansion or detail drawer on the
 * Certificates page. Self-contained: no UI library, inline styles matching
 * the Clear Ops look (light background, rounded cards, pill badges — red
 * expired / orange expiring / teal healthy — clean sans-serif).
 *
 * Props:
 *   certificate      {id, tenantId, name, domains?, thumbprint?, issuer?,
 *                     source ("key_vault"|"app_service"|"external"),
 *                     expiresAt (ISO), ownerName?, ownerEmail?}
 *   renewalState     null while loading, else the GET .../renewal response:
 *                    {policy: {autoRenewEnabled, enabledBy, enabledAt,
 *                              renewalWindowDays, effectiveDryRun,
 *                              renewalMethod}, recentAttempts: [...]}
 *   onEnable(windowDays)  -> Promise   PUT .../renewal/enable
 *   onDisable()           -> Promise   PUT .../renewal/disable
 *   onUpdateWindow(days)  -> Promise   PATCH .../renewal
 *   onUpdateMode(mode)    -> Promise   PATCH .../renewal {renewal_mode} (optional)
 *                             mode: "automatic" | "approval_required"
 *   onTriggerNow()        -> Promise   POST .../renewal/trigger  (optional)
 *
 * The parent owns data fetching and refetches renewalState after each
 * callback resolves; this component only renders state and collects intent.
 */

import React, { useMemo, useState } from "react";

const palette = {
  text: "#16243d",
  textSoft: "#5b6b84",
  textFaint: "#8b97ab",
  cardBg: "#ffffff",
  panelBg: "#f7f9fc",
  border: "#e4e9f1",
  red: "#d64545",
  redBg: "#fdecec",
  orange: "#d97f2c",
  orangeBg: "#fdf3e7",
  teal: "#1798a5",
  tealBg: "#e7f6f8",
  blue: "#2f6fd6",
  blueBg: "#eaf1fc",
  green: "#2e9e6b",
  greenBg: "#e9f7f0",
  gray: "#66738a",
  grayBg: "#eef1f6",
};

const METHOD_LABELS = {
  key_vault: { label: "Azure Key Vault", hint: "Re-issued via the vault's certificate policy" },
  app_service: { label: "Azure App Service", hint: "Managed certificate re-issued via the Azure management API" },
  acme: { label: "ACME (Let's Encrypt / ZeroSSL)", hint: "Re-issued with DNS-01 or HTTP-01 domain validation" },
  manual: { label: "Manual (Work Item)", hint: "Paid CA — a renewal Work Item is created for the certificate owner" },
};

const STATUS_STYLES = {
  succeeded: { color: palette.green, bg: palette.greenBg, label: "Succeeded" },
  failed: { color: palette.red, bg: palette.redBg, label: "Failed" },
  manual_required: { color: palette.orange, bg: palette.orangeBg, label: "Manual required" },
  in_progress: { color: palette.blue, bg: palette.blueBg, label: "In progress" },
  pending: { color: palette.gray, bg: palette.grayBg, label: "Pending" },
};

function Pill({ color, bg, children }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 10px",
        borderRadius: 999,
        fontSize: 12,
        fontWeight: 600,
        color,
        background: bg,
        whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function ExpiryPill({ expiresAt }) {
  const days = Math.floor((new Date(expiresAt) - Date.now()) / 86400000);
  if (days <= 0)
    return <Pill color={palette.red} bg={palette.redBg}>Expired</Pill>;
  if (days <= 30)
    return <Pill color={palette.orange} bg={palette.orangeBg}>{days} days</Pill>;
  return <Pill color={palette.teal} bg={palette.tealBg}>{days} days</Pill>;
}

function Toggle({ on, disabled, onChange }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      disabled={disabled}
      onClick={() => onChange(!on)}
      style={{
        width: 44,
        height: 24,
        borderRadius: 999,
        border: "none",
        padding: 2,
        cursor: disabled ? "not-allowed" : "pointer",
        background: on ? palette.blue : "#c6cfdd",
        opacity: disabled ? 0.6 : 1,
        transition: "background 0.15s ease",
        flexShrink: 0,
      }}
    >
      <span
        style={{
          display: "block",
          width: 20,
          height: 20,
          borderRadius: "50%",
          background: "#fff",
          boxShadow: "0 1px 2px rgba(22,36,61,0.25)",
          transform: on ? "translateX(20px)" : "translateX(0)",
          transition: "transform 0.15s ease",
        }}
      />
    </button>
  );
}

function SectionLabel({ children }) {
  return (
    <div
      style={{
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: "0.08em",
        textTransform: "uppercase",
        color: palette.textFaint,
        marginBottom: 8,
      }}
    >
      {children}
    </div>
  );
}

function formatDateTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

function AttemptRow({ attempt }) {
  const s = STATUS_STYLES[attempt.status] || STATUS_STYLES.pending;
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 12,
        padding: "10px 0",
        borderTop: `1px solid ${palette.border}`,
      }}
    >
      <Pill color={s.color} bg={s.bg}>{s.label}</Pill>
      {attempt.dryRun && (
        <Pill color={palette.gray} bg={palette.grayBg}>Dry run</Pill>
      )}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, color: palette.text }}>
          {formatDateTime(attempt.startedAt)}
          <span style={{ color: palette.textFaint }}>
            {" "}· attempt {attempt.attemptNumber} · {attempt.triggeredBy}
          </span>
        </div>
        {attempt.status === "succeeded" && attempt.newExpiresAt && (
          <div style={{ fontSize: 12, color: palette.green, marginTop: 2 }}>
            New expiry {formatDateTime(attempt.newExpiresAt)}
            {attempt.newThumbprint
              ? ` · ${attempt.newThumbprint.slice(0, 16)}…`
              : ""}
          </div>
        )}
        {attempt.error && (
          <div style={{ fontSize: 12, color: palette.red, marginTop: 2, overflowWrap: "anywhere" }}>
            {attempt.error}
          </div>
        )}
        {attempt.workItemId && (
          <div style={{ fontSize: 12, color: palette.orange, marginTop: 2 }}>
            Work Item {attempt.workItemId} created
          </div>
        )}
        {attempt.detail && !attempt.error && (
          <div style={{ fontSize: 12, color: palette.textSoft, marginTop: 2, overflowWrap: "anywhere" }}>
            {attempt.detail}
          </div>
        )}
      </div>
    </div>
  );
}

export default function CertificateRenewalPanel({
  certificate,
  renewalState,
  onEnable,
  onDisable,
  onUpdateWindow,
  onUpdateMode,
  onTriggerNow,
}) {
  const policy = renewalState?.policy;
  const attempts = renewalState?.recentAttempts || [];
  const enabled = !!policy?.autoRenewEnabled;

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [windowDraft, setWindowDraft] = useState(null);

  const windowDays = windowDraft ?? policy?.renewalWindowDays ?? 30;
  const method = METHOD_LABELS[policy?.renewalMethod] || METHOD_LABELS.manual;

  const daysLeft = useMemo(
    () => Math.floor((new Date(certificate.expiresAt) - Date.now()) / 86400000),
    [certificate.expiresAt]
  );
  const urgent = daysLeft <= 30;

  const run = async (fn) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e?.message || "Request failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        fontFamily:
          "'Inter','Segoe UI',system-ui,-apple-system,sans-serif",
        background: palette.cardBg,
        border: `1px solid ${palette.border}`,
        borderRadius: 14,
        padding: 20,
        maxWidth: 560,
        color: palette.text,
        boxShadow: "0 1px 3px rgba(22,36,61,0.06)",
      }}
    >
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <div style={{ fontSize: 15, fontWeight: 700, flex: 1, minWidth: 0, overflowWrap: "anywhere" }}>
          Automated renewal
        </div>
        <ExpiryPill expiresAt={certificate.expiresAt} />
        <Toggle
          on={enabled}
          disabled={busy || !renewalState}
          onChange={(next) =>
            run(() => (next ? onEnable(windowDays) : onDisable()))
          }
        />
      </div>
      <div style={{ fontSize: 13, color: palette.textSoft, marginBottom: 16 }}>
        {certificate.name}
        {certificate.issuer ? ` · ${certificate.issuer}` : ""}
      </div>

      {/* Urgency nudge when off */}
      {!enabled && urgent && (
        <div
          style={{
            background: daysLeft <= 0 ? palette.redBg : palette.orangeBg,
            color: daysLeft <= 0 ? palette.red : palette.orange,
            borderRadius: 10,
            padding: "10px 14px",
            fontSize: 13,
            marginBottom: 16,
          }}
        >
          {daysLeft <= 0
            ? `This certificate expired ${Math.abs(daysLeft)} days ago. Enable automated renewal to fix it now.`
            : `This certificate expires in ${daysLeft} days. Enable automated renewal so it never lapses.`}
        </div>
      )}

      {/* Opt-in provenance + dry-run notice */}
      {enabled && (
        <div style={{ fontSize: 12, color: palette.textFaint, marginBottom: 16 }}>
          Enabled by {policy.enabledBy || "unknown"} on {formatDateTime(policy.enabledAt)}
          {policy.effectiveDryRun && (
            <span style={{ marginLeft: 8 }}>
              <Pill color={palette.blue} bg={palette.blueBg}>Dry-run mode</Pill>
            </span>
          )}
        </div>
      )}

      {/* Method + window */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
        <div
          style={{
            flex: "1 1 220px",
            background: palette.panelBg,
            borderRadius: 10,
            padding: "12px 14px",
          }}
        >
          <SectionLabel>Renewal method</SectionLabel>
          <div style={{ fontSize: 14, fontWeight: 600 }}>{method.label}</div>
          <div style={{ fontSize: 12, color: palette.textSoft, marginTop: 2 }}>
            {method.hint}
          </div>
        </div>
        <div
          style={{
            flex: "1 1 160px",
            background: palette.panelBg,
            borderRadius: 10,
            padding: "12px 14px",
          }}
        >
          <SectionLabel>Renew before expiry</SectionLabel>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <input
              type="number"
              min={1}
              max={365}
              value={windowDays}
              disabled={busy || !renewalState}
              onChange={(e) => setWindowDraft(Number(e.target.value))}
              onBlur={() => {
                if (
                  windowDraft != null &&
                  windowDraft >= 1 &&
                  windowDraft <= 365 &&
                  windowDraft !== policy?.renewalWindowDays &&
                  enabled
                ) {
                  run(() => onUpdateWindow(windowDraft));
                }
              }}
              style={{
                width: 64,
                padding: "6px 8px",
                borderRadius: 8,
                border: `1px solid ${palette.border}`,
                fontSize: 14,
                color: palette.text,
                background: "#fff",
              }}
            />
            <span style={{ fontSize: 13, color: palette.textSoft }}>days</span>
          </div>
        </div>
      </div>

      {/* Renewal mode: fully automatic vs human approval per cycle */}
      {enabled && onUpdateMode && (
        <div
          style={{
            background: palette.panelBg,
            borderRadius: 10,
            padding: "12px 14px",
            marginBottom: 16,
          }}
        >
          <SectionLabel>Renewal mode</SectionLabel>
          <div style={{ display: "flex", gap: 8 }}>
            {[
              ["automatic", "Automatic"],
              ["approval_required", "Require approval"],
            ].map(([value, label]) => {
              const active = (policy.renewalMode || "automatic") === value;
              return (
                <button
                  key={value}
                  type="button"
                  disabled={busy || active}
                  onClick={() => run(() => onUpdateMode(value))}
                  style={{
                    padding: "6px 12px",
                    borderRadius: 999,
                    fontSize: 13,
                    fontWeight: 600,
                    cursor: busy || active ? "default" : "pointer",
                    border: `1px solid ${active ? palette.blue : palette.border}`,
                    background: active ? palette.blueBg : "#fff",
                    color: active ? palette.blue : palette.textSoft,
                  }}
                >
                  {label}
                </button>
              );
            })}
          </div>
          {(policy.renewalMode || "automatic") === "approval_required" && (
            <div style={{ fontSize: 12, color: palette.textSoft, marginTop: 8 }}>
              Each renewal cycle pauses until someone approves it in the
              renewal approvals queue.
            </div>
          )}
        </div>
      )}

      {/* Manual trigger */}
      {enabled && onTriggerNow && (
        <button
          type="button"
          disabled={busy}
          onClick={() => run(onTriggerNow)}
          style={{
            border: `1px solid ${palette.border}`,
            background: "#fff",
            color: palette.blue,
            borderRadius: 10,
            padding: "8px 14px",
            fontSize: 13,
            fontWeight: 600,
            cursor: busy ? "wait" : "pointer",
            marginBottom: 16,
          }}
        >
          {busy ? "Working…" : "Run renewal now"}
        </button>
      )}

      {error && (
        <div
          style={{
            background: palette.redBg,
            color: palette.red,
            borderRadius: 10,
            padding: "8px 12px",
            fontSize: 13,
            marginBottom: 16,
          }}
        >
          {error}
        </div>
      )}

      {/* Attempt history */}
      <SectionLabel>Recent renewal attempts</SectionLabel>
      {!renewalState ? (
        <div style={{ fontSize: 13, color: palette.textFaint }}>Loading…</div>
      ) : attempts.length === 0 ? (
        <div style={{ fontSize: 13, color: palette.textFaint }}>
          No attempts yet.
          {enabled
            ? " The next scheduled sweep will pick this certificate up once it enters its renewal window."
            : " Enable automated renewal to start."}
        </div>
      ) : (
        <div>
          {attempts.map((a) => (
            <AttemptRow key={a.id} attempt={a} />
          ))}
        </div>
      )}
    </div>
  );
}
