use serde::Deserialize;
use super::BootstrapProvider;
use std::error::Error;

pub struct HttpProvider {
    pub url: String,
}

impl BootstrapProvider for HttpProvider {
    fn fetch_payload(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        let resp = ureq::get(&self.url)
            .timeout(std::time::Duration::from_secs(15))
            .call()?;
        let text = resp.into_string()?;
        Ok(text)
    }

    fn name(&self) -> String {
        format!("HTTP({})", self.url)
    }
}

pub struct DohProvider {
    pub domain: String,
    pub resolver_url: String,
}

#[derive(Deserialize)]
struct DohResponse {
    #[serde(rename = "Answer")]
    answer: Option<Vec<DohAnswer>>,
}

#[derive(Deserialize)]
struct DohAnswer {
    data: String,
}

impl BootstrapProvider for DohProvider {
    fn fetch_payload(&self) -> Result<String, Box<dyn Error + Send + Sync>> {
        let url = format!("{}?name={}&type=TXT", self.resolver_url, self.domain);
        let resp: DohResponse = ureq::get(&url)
            .timeout(std::time::Duration::from_secs(15))
            .call()?
            .into_json()?;

        if let Some(answers) = resp.answer {
            for answer in answers {
                let raw_txt = answer.data.trim_matches('"').replace("\\\"", "\"");
                if raw_txt.contains("SIG:") {
                    return Ok(raw_txt);
                }
            }
        }
        Err(format!("No signed TXT record found for {}", self.domain).into())
    }

    fn name(&self) -> String {
        format!("DoH({} @ {})", self.domain, self.resolver_url)
    }
}
