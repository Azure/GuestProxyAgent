// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use std::borrow::Cow;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

const REDACTED_TEXT: &str = "[REDACTED]";
// Each Regex keeps a lazy-DFA cache. Keep it small because this module has several expressions.
// Starts with 1MB, but can be tuned down if needed.
const REGEX_DFA_SIZE_LIMIT: usize = 1024 * 1024;
/// Common substrings that indicate a secret might be present - for quick pre-filtering
/// These are not regex patterns, just simple substrings to check for before running the more expensive regexes.
const SECRET_INDICATORS: [&str; 15] = [
    "pwd=",
    "password=",
    "AccountKey=",
    "PrimaryKey=",
    "SecondaryKey=",
    "sig=",
    "AzCa",
    "PRIVATE KEY",
    "token",
    "ado",
    "vsts",
    "key",
    "secret",
    "authorization",
    "eyJ",
];
/// Regular expression patterns to identify secrets. These are more expensive to run, so we first check for indicators.
/// Remarks: when add more patterns, please also add corresponding indicators in SECRET_INDICATORS for better performance.
///     And try to make the pattern as specific as possible to avoid false positives and unnecessary redaction.
const CRED_PATTERNS: [&str; 17] = [
            // SQL Connection String Password
            "pwd=[^;]*", 
            "password=[^;]*",
            // Azure Storage Connection String Keys
            "AccountKey=[^;]*", 
            "PrimaryKey=[^;]*", 
            "SecondaryKey=[^;]*", 
            // SAS Key
            "sig=[^&]*",
            // Azure Redis Cache Secret (Identifiable)
            r"(?-i)([0-9a-zA-Z]{33}AzCa[A-P][0-9a-zA-Z]{5}=)|([0-9a-zA-Z]{44}AzCa[0-9a-zA-Z]{5}[AQgw])",
            // X.509 Certificate Private Key
            r"BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY",
            // Azure DevOps Personal Access Token
            r"(?i)(pat[\\s\\W]|token|ado|vsts|azuredevops|visualstudio\\.com|dev\\.azure\\.com).([a-z2-7]{52}|[A-Z2-7]{52})",
            // Azure Storage Account Access Key
            "(?i)(key|access|sas|shared|secret|password|pwd|pswd|credential)[\\s\\S]{0,200}[^a-z0-9/+]([a-z0-9/+]{43}=)",
            "(?i)(azurecr[\\s\\S]{0,50}|pwd|pswd|password)[:\\s=]+([a-z0-9/{\\}{\\+}=\\-!#$%&()*,./:;?@[\\]^_`{|}~+<=>\\s]+){0,50}",
            "(?i)(key|access|sas|shared|secret|password|pswd|pwd|credential)[\\s\\S]{0,200}[^a-z0-9/+]([a-z0-9/+]{86}=)",
            // Microsoft Entra Client Secret/Identifiable/Access Token
            "(?i)(\\Waws|amazon)?.{0,5}(secret|access.?(key|token)).{0,10}[^/,\\w\\+\\$\\-][a-z0-9/\\+]{40}\\W",
            "(?i)((app(lication)?|client|api)[_ \\-]?(se?cre?t|key(url)?)|(refresh|twilio(account|auth))[_ \\-]?(Sid|Token))([\\s=:>]{1,10}|[\\s\"':=|>,\\]\\\\]{3,15}|[\"'=:\\(]{2})(ConvertTo-SecureString[^\"']+[\"'])?(\"data:text/plain,.+\"|[a-z0-9/+=_.\\?\\-]{8,200}[^\\(\\[\\{;,\\r\\n]|[^\\s\"';<,\\)]{5,200})",
            "(?-i)eyJ(?i)[a-z0-9\\-_%]+\\.(?-i)eyJ",
            // General Password
            "(?i)((amqp|ssh|(ht|f)tps?)://[^%:\\s\"'/][^:\\s\"'/\\$]+[^:\\s\"'/\\$%]:([^%\\s\"'/][^@\\s\"'/]{0,100}[^%\\s\"'/])@[\\$a-z0-9:\\._%\\?=/]+|[a-z0-9]{3,5}://[^%:\\s\"'/][^:\\s\"'/\\$]+[^:\\s\"'/\\$%]:([^%\\s\"'/][^@\\s\"'/]{0,100}[^%\\s\"'/])@[\\$a-z0-9:\\._%\\?=/\\-]+)",
            // Http Authorization Header
            "(?i)authorization[,\\[:= \"'\\s]+(value[,\\[:= \"'\\s]+)?(basic|digest|hoba|mutual|negotiate|oauth( oauth_token=)?|(http[^ ]+/saml\\d\\-)?bearer [^e\"'&]|scram\\-sha\\-1|scram\\-sha\\-256|vapid|aws4\\-hmac\\-sha256).*",
        ];

struct RedactionRequest {
    text: String,
    response_sender: SyncSender<String>,
}

static REDACTION_SENDER: once_cell::sync::Lazy<SyncSender<RedactionRequest>> =
    once_cell::sync::Lazy::new(|| {
        let (sender, receiver) = sync_channel(0);
        std::thread::Builder::new()
            .name("secret-redactor".to_string())
            .spawn(move || run_redaction_worker(receiver))
            .expect("failed to start secret redaction thread");
        sender
    });

fn init_regex_patterns() -> Vec<regex::Regex> {
    let mut patterns = Vec::new();
    for pattern in CRED_PATTERNS.iter() {
        if let Ok(re) = regex::RegexBuilder::new(pattern)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
        {
            patterns.push(re);
        }
    }
    patterns
}

fn run_redaction_worker(receiver: Receiver<RedactionRequest>) {
    let patterns = init_regex_patterns();
    while let Ok(request) = receiver.recv() {
        let redacted_text = redact_secrets(&patterns, &request.text);
        let response = match redacted_text {
            Cow::Borrowed(_) => request.text,
            Cow::Owned(text) => text,
        };
        let _ = request.response_sender.send(response);
    }
}

/// Quick check if text might contain secrets (case-insensitive for most indicators)
#[inline]
fn might_contain_secrets(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECRET_INDICATORS.iter().any(|indicator| {
        if *indicator == "AzCa" || *indicator == "PRIVATE KEY" || *indicator == "eyJ" {
            // Case-sensitive check for these
            text.contains(indicator)
        } else {
            lower.contains(&indicator.to_ascii_lowercase())
        }
    })
}

/// Redacts secrets from text. Returns the original text unchanged if no secrets found.
/// Takes `&str` to avoid unnecessary ownership transfer.
fn redact_secrets<'a>(patterns: &[regex::Regex], text: &'a str) -> Cow<'a, str> {
    let mut redacted_text = Cow::Borrowed(text);
    for pattern in patterns {
        if let Cow::Owned(s) = pattern.replace_all(&redacted_text, REDACTED_TEXT) {
            redacted_text = Cow::Owned(s);
        }
    }
    redacted_text
}

/// Convenience function that takes ownership and returns String
/// Use this when you already have a String and need a String back
///
/// This function sends regex work to a dedicated thread and can therefore block briefly. Call it
/// only from a non-critical logging or telemetry-consumer path, not while processing a proxied
/// request.
#[inline]
pub fn redact_secrets_string(text: String) -> String {
    if text.is_empty() || !might_contain_secrets(&text) {
        return text;
    }

    let (response_sender, response_receiver) = sync_channel(1);
    REDACTION_SENDER
        .send(RedactionRequest {
            text,
            response_sender,
        })
        .expect("secret redaction thread stopped unexpectedly");
    response_receiver
        .recv()
        .expect("secret redaction thread stopped before responding")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secrets() {
        let patterns = init_regex_patterns();
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
            assert_eq!(redact_secrets(&patterns, input), expected);
        }
    }

    #[test]
    fn test_no_secrets_no_allocation() {
        let patterns = init_regex_patterns();
        let text = "This is a normal log message without any secrets";
        let result = redact_secrets(&patterns, text);
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

    #[test]
    fn test_redact_secrets_from_concurrent_callers() {
        let callers: Vec<_> = (0..8)
            .map(|index| {
                std::thread::spawn(move || {
                    let text = format!("request={index};password=secret{index};");
                    redact_secrets_string(text)
                })
            })
            .collect();

        for (index, caller) in callers.into_iter().enumerate() {
            assert_eq!(
                caller.join().expect("redaction caller panicked"),
                format!("request={index};[REDACTED];")
            );
        }
    }
}
