//! Подбор замены сервера, который перестал отвечать.
//!
//! Кандидаты делятся на ступени по настройке `switch_order`: сначала серверы
//! с таким же типом подключения, затем из той же страны и т.д., в конце —
//! все остальные. Приложение проверяет ступень целиком и берёт самый быстрый
//! рабочий сервер; если в ступени ни один не ответил — переходит к следующей.

use crate::model::Server;

/// Сервер-кандидат вместе с id его подписки.
pub struct Candidate<'a> {
    pub sub_id: &'a str,
    pub server: &'a Server,
}

/// Ступени замены для сервера `current`. Каждый сервер попадает в одну
/// ступень. Российские серверы («белые списки») меняются только на
/// российские, зарубежные — только на зарубежные: иначе при включённых
/// белых списках приложение ушло бы на сервер, который там не работает,
/// а без них сайты увидели бы российский IP.
pub fn tiers(current: &Server, current_sub: &str, all: &[Candidate], order: &[String]) -> Vec<Vec<String>> {
    let domestic = current.is_domestic();
    let mut seen = std::collections::HashSet::new();
    seen.insert(current.id.clone());
    let pool: Vec<&Candidate> = all
        .iter()
        .filter(|c| c.server.usable() && c.server.is_domestic() == domestic)
        .filter(|c| seen.insert(c.server.id.clone()))
        .collect();
    let kind = current.kind();
    let country = current.country();
    let mut placed = std::collections::HashSet::new();
    let mut out = vec![];
    for crit in order {
        let tier: Vec<String> = pool
            .iter()
            .filter(|c| !placed.contains(&c.server.id))
            .filter(|c| match crit.as_str() {
                "type" => c.server.kind() == kind,
                "country" => country.is_some() && c.server.country() == country,
                "subscription" => c.sub_id == current_sub,
                _ => false,
            })
            .map(|c| c.server.id.clone())
            .collect();
        if !tier.is_empty() {
            placed.extend(tier.iter().cloned());
            out.push(tier);
        }
    }
    let rest: Vec<String> = pool
        .iter()
        .filter(|c| !placed.contains(&c.server.id))
        .map(|c| c.server.id.clone())
        .collect();
    if !rest.is_empty() {
        out.push(rest);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn srv(id: &str, name: &str, transport: &str) -> Server {
        Server {
            id: id.into(),
            name: name.into(),
            link: String::new(),
            protocol: "vless".into(),
            address: "a".into(),
            port: 443,
            transport: transport.into(),
            outbound: Some(json!({})),
            xray: None,
            error: None,
        }
    }

    #[test]
    fn same_type_then_country_then_rest() {
        let nl_x = srv("nl_x", "🇳🇱 Нидерланды", "xhttp · reality");
        let de_x = srv("de_x", "🇩🇪 Германия", "xhttp · reality");
        let nl_t = srv("nl_t", "🇳🇱 Нидерланды 2", "tcp · reality");
        let fi_t = srv("fi_t", "🇫🇮 Финляндия", "tcp · reality");
        let ru = srv("ru", "🇷🇺 Белый интернет", "xhttp · tls");
        let all = [&nl_x, &de_x, &nl_t, &fi_t, &ru]
            .iter()
            .map(|s| Candidate { sub_id: "a", server: s })
            .collect::<Vec<_>>();
        let order = vec!["type".to_string(), "country".to_string()];
        let t = tiers(&nl_x, "a", &all, &order);
        assert_eq!(t, vec![vec!["de_x".to_string()], vec!["nl_t".into()], vec!["fi_t".into()]]);
        // Российский сервер меняется только на российский.
        let t = tiers(&ru, "a", &all, &order);
        assert!(t.is_empty());
        assert_eq!(nl_x.country().as_deref(), Some("NL"));
        assert_eq!(nl_x.kind(), "vless xhttp");
    }
}
