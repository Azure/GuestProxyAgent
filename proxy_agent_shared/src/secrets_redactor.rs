// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use std::borrow::Cow;

const REDACTED_TEXT: &str = "[REDACTED]";

/// Replaces every occurrence of `prefix + <chars up to stop_char>` with REDACTED_TEXT.
/// Case-sensitive. Returns `None` when the prefix is absent (no allocation).
fn redact_prefixed(text: &str, prefix: &str, stop_char: char) -> Option<String> {
    if !text.contains(prefix) {
        return None;
    }
    let mut result = String::with_capacity(text.len());
    let mut remaining = text;
    while let Some(pos) = remaining.find(prefix) {
        result.push_str(&remaining[..pos]);
        result.push_str(REDACTED_TEXT);
        let after = &remaining[pos + prefix.len()..];
        let skip = after.find(stop_char).unwrap_or(after.len());
        remaining = &after[skip..];
    }
    result.push_str(remaining);
    Some(result)
}

/// Applies a compiled regex to the current Cow, returning the (possibly modified) Cow.
#[inline]
fn apply_re<'a>(text: Cow<'a, str>, re: &regex::Regex) -> Cow<'a, str> {
    match re.replace_all(&text, REDACTED_TEXT) {
        Cow::Borrowed(_) => text, // no match – preserve the existing Cow as-is
        Cow::Owned(s) => Cow::Owned(s),
    }
}

/// Redacts secrets from text.
///
/// Design: two-pass approach to minimise both memory and CPU:
///
/// **Part 1** – Six simple `prefix=[^delimiter]*` patterns are handled with plain
/// string scanning (`redact_prefixed`), removing the need for six compiled `Regex`
/// objects entirely.
///
/// **Part 2** – Each remaining complex pattern is stored in its own `LazyLock<Regex>`
/// static and is only compiled (once, on first use) when its specific indicator is
/// actually present in the text.  This means patterns for rare indicators such as
/// `"AzCa"`, `"PRIVATE KEY"`, and `"eyJ"` will never consume heap in environments
/// where those strings never appear in log output.
///
/// Returns the original text as `Cow::Borrowed` when nothing is redacted.
fn redact_secrets(text: &str) -> Cow<'_, str> {
    if text.is_empty() {
        return Cow::Borrowed(text);
    }
    // Compute the lowercased version once for all case-insensitive indicator checks.
    let lower = text.to_ascii_lowercase();
    let mut out: Cow<str> = Cow::Borrowed(text);

    // ── Part 1: simple literal-prefix patterns (no regex required) ───────────
    // Pattern: `pwd=[^;]*`
    if let Some(s) = redact_prefixed(&out, "pwd=", ';') {
        out = Cow::Owned(s);
    }
    // Pattern: `password=[^;]*`
    if let Some(s) = redact_prefixed(&out, "password=", ';') {
        out = Cow::Owned(s);
    }
    // Pattern: `AccountKey=[^;]*`
    if let Some(s) = redact_prefixed(&out, "AccountKey=", ';') {
        out = Cow::Owned(s);
    }
    // Pattern: `PrimaryKey=[^;]*`
    if let Some(s) = redact_prefixed(&out, "PrimaryKey=", ';') {
        out = Cow::Owned(s);
    }
    // Pattern: `SecondaryKey=[^;]*`
    if let Some(s) = redact_prefixed(&out, "SecondaryKey=", ';') {
        out = Cow::Owned(s);
    }
    // Pattern: `sig=[^&]*`
    if let Some(s) = redact_prefixed(&out, "sig=", '&') {
        out = Cow::Owned(s);
    }

    // ── Part 2: complex patterns – per-indicator dispatch ────────────────────
    // Each static is compiled lazily the first time its indicator fires; patterns
    // whose indicators never appear in a deployment are never compiled at all.

    // Azure Redis Cache Secret  (indicator: "AzCa", case-sensitive)
    if out.contains("AzCa") {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"(?-i)([0-9a-zA-Z]{33}AzCa[A-P][0-9a-zA-Z]{5}=)|([0-9a-zA-Z]{44}AzCa[0-9a-zA-Z]{5}[AQgw])",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // X.509 Certificate Private Key  (indicator: "PRIVATE KEY", case-sensitive)
    if out.contains("PRIVATE KEY") {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(r"BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY")
                .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // Azure DevOps Personal Access Token  (indicators: token, ado, vsts)
    if lower.contains("token") || lower.contains("ado") || lower.contains("vsts") {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                r"(?i)(pat[\\s\\W]|token|ado|vsts|azuredevops|visualstudio\\.com|dev\\.azure\\.com).([a-z2-7]{52}|[A-Z2-7]{52})",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // Azure Storage Account Access Key – 43 chars
    // (indicators: key, access, sas, secret, password, pwd, credential)
    if lower.contains("key")
        || lower.contains("access")
        || lower.contains("sas")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("pwd")
        || lower.contains("credential")
    {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                "(?i)(key|access|sas|shared|secret|password|pwd|pswd|credential)[\\s\\S]{0,200}[^a-z0-9/+]([a-z0-9/+]{43}=)",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // Azure Container Registry credential  (indicators: pwd, password, azurecr)
    // Note: the original pattern had an unescaped `[` inside the character class which
    // caused a silent compile failure in the previous implementation; `\[` fixes it.
    if lower.contains("pwd") || lower.contains("password") || lower.contains("azurecr") {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                "(?i)(azurecr[\\s\\S]{0,50}|pwd|pswd|password)[:\\s=]+([a-z0-9/{\\}{\\+}=\\-!#$%&()*,./:;?@\\[\\]^_`{|}~+<=>\\s]+){0,50}",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // Azure Storage Account Access Key – 86 chars  (same indicators as 43-char variant)
    if lower.contains("key")
        || lower.contains("access")
        || lower.contains("sas")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("pwd")
        || lower.contains("credential")
    {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                "(?i)(key|access|sas|shared|secret|password|pswd|pwd|credential)[\\s\\S]{0,200}[^a-z0-9/+]([a-z0-9/+]{86}=)",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // Microsoft Entra / AWS access token  (indicators: secret, access, key, token)
    if lower.contains("secret")
        || lower.contains("access")
        || lower.contains("key")
        || lower.contains("token")
    {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                "(?i)(\\Waws|amazon)?.{0,5}(secret|access.?(key|token)).{0,10}[^/,\\w\\+\\$\\-][a-z0-9/\\+]{40}\\W",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // Application / client secret  (indicators: secret, key, token)
    if lower.contains("secret") || lower.contains("key") || lower.contains("token") {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                "(?i)((app(lication)?|client|api)[_ \\-]?(se?cre?t|key(url)?)|(refresh|twilio(account|auth))[_ \\-]?(Sid|Token))([\\s=:>]{1,10}|[\\s\"':=|>,\\]\\\\]{3,15}|[\"'=:\\(]{2})(ConvertTo-SecureString[^\"']+[\"'])?(\"data:text/plain,.+\"|[a-z0-9/+=_.\\?\\-]{8,200}[^\\(\\[\\{;,\\r\\n]|[^\\s\"';<,\\)]{5,200})",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // JWT / Entra access token  (indicator: "eyJ", case-sensitive)
    if out.contains("eyJ") {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(r"(?-i)eyJ(?i)[a-z0-9\-_%]+\.(?-i)eyJ").unwrap()
        });
        out = apply_re(out, &RE);
    }

    // General URL credential – amqp/ssh/https URL with embedded user:password@host
    // Using structural indicators ("://" and "@") avoids triggering on the broad
    // "key"/"secret" indicators that appear in almost every log line.
    if text.contains("://") && text.contains('@') {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                "(?i)((amqp|ssh|(ht|f)tps?)://[^%:\\s\"'/][^:\\s\"'/\\$]+[^:\\s\"'/\\$%]:([^%\\s\"'/][^@\\s\"'/]{0,100}[^%\\s\"'/])@[\\$a-z0-9:\\._%\\?=/]+|[a-z0-9]{3,5}://[^%:\\s\"'/][^:\\s\"'/\\$]+[^:\\s\"'/\\$%]:([^%\\s\"'/][^@\\s\"'/]{0,100}[^%\\s\"'/])@[\\$a-z0-9:\\._%\\?=/\\-]+)",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    // HTTP Authorization header  (indicator: "authorization")
    if lower.contains("authorization") {
        static RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(
                "(?i)authorization[,\\[:= \"'\\s]+(value[,\\[:= \"'\\s]+)?(basic|digest|hoba|mutual|negotiate|oauth( oauth_token=)?|(http[^ ]+/saml\\d\\-)?bearer [^e\"'&]|scram\\-sha\\-1|scram\\-sha\\-256|vapid|aws4\\-hmac\\-sha256).*",
            )
            .unwrap()
        });
        out = apply_re(out, &RE);
    }

    out
}

/// Convenience function that takes ownership and returns String
/// Use this when you already have a String and need a String back
#[inline]
pub fn redact_secrets_string(text: String) -> String {
    match redact_secrets(&text) {
        Cow::Borrowed(_) => text, // No changes, return original
        Cow::Owned(s) => s,       // Changed, return new string
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secrets() {
        let test_strings = vec![
            (
                "server=...database.windows.net;database=...;pwd=<dummyString>;user=...;",
                "server=...database.windows.net;database=...;[REDACTED];user=...;",
            ),
            (
                "server=...database.windows.net;database=...;password=<dummyString>;user=...;",
                "server=...database.windows.net;database=...;[REDACTED];user=...;",
            ),
            (
                "https://abc.core.windows.net/blob?sig=<dummyKey>&otherparam=value",
                "https://abc.core.windows.net/blob?[REDACTED]&otherparam=value",
            ),
            (
                "Endpoint=...table.core.windows.net;AccountKey=<dummyString>;AccountName=...",
                "Endpoint=...table.core.windows.net;[REDACTED];AccountName=...",
            ),
            (
                "Endpoint=...table.core.windows.net;PrimaryKey=<dummyString>;AccountName=...",
                "Endpoint=...table.core.windows.net;[REDACTED];AccountName=...",
            ),
            (
                "Endpoint=...table.core.windows.net;SecondaryKey=<dummyString>;AccountName=...",
                "Endpoint=...table.core.windows.net;[REDACTED];AccountName=...",
            ),
            (
                "https://example.com/api?sig=<dummyKey>",
                "https://example.com/api?[REDACTED]",
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMI...\n-----END RSA PRIVATE KEY-----",
                "-----[REDACTED]-----",
            ),
            (
                r#"Here is a token:abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst
And another one: azuredevops=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"#,
                "Here is a [REDACTED]\nAnd another one: [REDACTED]",
            ),
            (
                r#"Here is one: abcdefghijklmnopqrstuvwxyzABCDEFGAzCaG12345=
Another one: 1234567890abcdefghijklmnopqrstuvwxyzABC12345AzCaabcdeQ"#,
                "Here is one: [REDACTED]\nAnother one: [REDACTED]",
            ),
            (
                "EntraAccessToken:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtest",
                "EntraAccessToken:[REDACTED]test",
            ),
            (
                r#"Authorization: Bearer abcdef123456
authorization = basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
Authorization value: oauth oauth_token=xyz
authorization: aws4-hmac-sha256"#,
                "[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]",
            ),
        ];
        for (input, expected) in test_strings {
            assert_eq!(redact_secrets(input), expected);
        }
    }

    #[test]
    fn test_no_secrets_no_allocation() {
        let text = "This is a normal log message without any secrets";
        let result = redact_secrets(text);
        // Should return Borrowed (no allocation) when no secrets found
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_secrets_string() {
        let text = "pwd=secret123;".to_string();
        let result = redact_secrets_string(text);
        assert_eq!(result, "[REDACTED];");
    }
}
