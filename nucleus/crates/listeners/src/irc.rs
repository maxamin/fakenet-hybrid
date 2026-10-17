//! IRC (RFC 1459, RFC 2812), a classic botnet C2 channel. Each client message is an event
//! (`meta.command`, `meta.params`, `meta.nick`); a daemon response replaces the reply, so a
//! rule can e.g. answer a JOIN with ":boss!b@c2 PRIVMSG #chan :!download http://..." to see
//! what the bot does with a command.

use serde_json::json;

use crate::lines::Lines;
use crate::session::Session;
use crate::stream::BoxStream;

/// (command, parameters), handling the optional ":prefix" and the trailing ":parameter"
/// which may contain spaces (RFC 2812 2.3.1)
pub fn parse_message(line: &str) -> (String, Vec<String>) {
    let mut rest = line.trim_start();
    if rest.starts_with(':') {
        rest = rest.split_once(' ').map(|(_, r)| r).unwrap_or("");
    }
    let (middle, trailing) = match rest.split_once(" :") {
        Some((middle, trailing)) => (middle, Some(trailing)),
        None => (rest, None),
    };
    let mut words = middle.split_whitespace();
    let command = words.next().unwrap_or("").to_ascii_uppercase();
    let mut params: Vec<String> = words.map(str::to_string).collect();
    params.extend(trailing.map(str::to_string));
    (command, params)
}

pub async fn handle(stream: BoxStream, mut session: Session) -> anyhow::Result<()> {
    let server = session.ctx.defaults.irc.server_name.clone();
    let mut lines = Lines::new(stream);
    let mut nick = "*".to_string();
    let mut user = "user".to_string();
    let mut registered = false;
    let mut user_seen = false;

    while let Some(line) = lines.read(&session).await? {
        let (command, params) = parse_message(&line);
        let p = |i: usize| params.get(i).cloned().unwrap_or_default();
        let mask = format!("{nick}!{user}@fakenet");
        let mut reply = String::new();
        let mut close = false;
        match command.as_str() {
            "PASS" => session.log("credentials", json!({ "password": p(0) })),
            "NICK" => nick = p(0),
            "USER" => {
                user = p(0);
                user_seen = true;
            }
            "CAP" if p(0).eq_ignore_ascii_case("LS") => reply = format!(":{server} CAP * LS :\r\n"),
            "CAP" | "PONG" => {}
            "PING" => reply = format!(":{server} PONG {server} :{}\r\n", p(0)),
            "JOIN" => {
                session.log("join", json!({ "nick": nick, "channels": p(0), "keys": p(1) }));
                for channel in p(0).split(',').filter(|c| !c.is_empty()) {
                    reply.push_str(&format!(
                        ":{mask} JOIN {channel}\r\n:{server} 332 {nick} {channel} :FakeNet\r\n\
                         :{server} 353 {nick} = {channel} :{nick} @botmaster\r\n:{server} 366 {nick} {channel} :End of /NAMES list.\r\n"
                    ));
                }
            }
            "PART" => reply = format!(":{mask} PART {}\r\n", p(0)),
            "PRIVMSG" | "NOTICE" => session.log("message", json!({ "command": command, "nick": nick, "target": p(0), "text": p(1) })),
            "MODE" => reply = format!(":{server} 221 {nick} +i\r\n"),
            "WHO" => reply = format!(":{server} 315 {nick} {} :End of /WHO list.\r\n", p(0)),
            "USERHOST" => reply = format!(":{server} 302 {nick} :{nick}=+{user}@fakenet\r\n"),
            "ISON" => reply = format!(":{server} 303 {nick} :{}\r\n", params.join(" ")),
            "QUIT" => {
                session.log("quit", json!({ "nick": nick, "message": p(0) }));
                reply = format!("ERROR :Closing Link: {nick} (Quit)\r\n");
                close = true;
            }
            _ => reply = format!(":{server} 421 {nick} {command} :Unknown command\r\n"),
        }
        // Registration completes once both NICK & USER have arrived, in either order
        if !registered && nick != "*" && user_seen {
            registered = true;
            session.log("registered", json!({ "nick": nick, "user": user }));
            reply.push_str(&format!(
                ":{server} 001 {nick} :Welcome to the FakeNet IRC Network {nick}!{user}@fakenet\r\n\
                 :{server} 002 {nick} :Your host is {server}, running version FakeNet\r\n\
                 :{server} 003 {nick} :This server was created today\r\n\
                 :{server} 004 {nick} {server} FakeNet o o\r\n\
                 :{server} 375 {nick} :- {server} Message of the day -\r\n\
                 :{server} 372 {nick} :- Welcome to FakeNet\r\n\
                 :{server} 376 {nick} :End of /MOTD command.\r\n"
            ));
        }
        let meta = json!({ "command": command, "params": params, "nick": nick, "registered": registered });
        if !lines.respond(&mut session, line.as_bytes(), meta, reply, close).await? {
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_messages() {
        assert_eq!(parse_message(":n!u@h PRIVMSG #c :hello there"), ("PRIVMSG".into(), vec!["#c".into(), "hello there".into()]));
        assert_eq!(parse_message("join #a,#b key"), ("JOIN".into(), vec!["#a,#b".into(), "key".into()]));
    }
}
