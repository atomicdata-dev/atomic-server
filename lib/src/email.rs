//! [EmailAddress] with validation, [MailMessage] with sending, and [get_smtp_client] for setting up mail.

use crate::{errors::AtomicResult, storelike::Query, urls, Storelike};
use mail_send::{mail_builder::MessageBuilder, Connected, Transport};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmailAddress {
    pub address: String,
}

impl EmailAddress {
    pub fn new(address: String) -> AtomicResult<Self> {
        // TODO: use decent crate for validation, like Lettre
        if !address.contains('@') {
            return Err(format!("Invalid email address: {}", address).into());
        }
        Ok(Self { address })
    }

    /// Throws error if email address is already taken
    pub fn check_used(self, store: &impl Storelike) -> AtomicResult<Self> {
        let mut query = Query::new();
        // TODO: This hits too many resources, as it will also include non-agent resources
        query.property = Some(urls::EMAIL.into());
        query.value = Some(crate::Value::String(self.address.clone()));
        if store.query(&query)?.count > 0 {
            return Err("Email address already used".into());
        }
        Ok(self)
    }
}

impl std::fmt::Display for EmailAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
}

pub async fn get_smtp_client(
    config: SmtpConfig,
) -> AtomicResult<mail_send::Transport<'static, Connected>> {
    let full_address = format!("{}:{}", config.host, config.port);
    info!("Connecting to mailserver {full_address}");
    let connection = Transport::new(config.host.clone())
        .port(config.port)
        .connect()
        .await
        .map_err(|e| format!("Error connecting to SMTP mail server: at {full_address}. Is it running? Error message: {e}"))?;
    Ok(connection)
}

#[derive(Debug)]
pub struct MailMessage {
    pub to: EmailAddress,
    pub subject: String,
    pub body: String,
    pub action: Option<MailAction>,
}

#[derive(Debug)]
pub struct MailAction {
    pub name: String,
    pub url: String,
}

#[tracing::instrument(skip(connection))]
pub async fn send_mail(
    connection: &mut mail_send::Transport<'static, Connected>,
    message: MailMessage,
) -> AtomicResult<()> {
    let html = if let Some(action) = message.action {
        format!(
            "{}<br><a href=\"{}\">{}</a>",
            message.body, action.url, action.name
        )
    } else {
        message.body.clone()
    };

    let builder = MessageBuilder::new()
        .from(("Atomic Data", "noreply@atomicdata.dev"))
        .to(vec![(message.to.to_string())])
        .subject(message.subject)
        .html_body(html)
        .text_body(message.body);
    info!("Sending mail");
    connection.send(builder).await.map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn create_and_serialize_email() {
        EmailAddress::new("invalid email".into()).unwrap_err();
        let valid = EmailAddress::new("valid@email.com".into()).unwrap();
        assert_eq!(valid.to_string(), "valid@email.com");
    }
}
