//! A JSON reader for the registry's answers (`--pull`): manifests, image
//! indexes and token responses.

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Parse `text`, which must be one value (with whitespace around it).
    pub fn parse(text: &str) -> Result<Json, String> {
        let mut p = Parser { s: text.as_bytes(), at: 0 };
        let v = p.value()?;
        p.space();
        if p.at != p.s.len() {
            return Err(format!("JSON: trailing text at byte {}", p.at));
        }
        Ok(v)
    }

    /// The member `key` of an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn arr(&self) -> &[Json] {
        match self {
            Json::Arr(items) => items,
            _ => &[],
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn space(&mut self) {
        while self.s.get(self.at).is_some_and(|c| c.is_ascii_whitespace()) {
            self.at += 1;
        }
    }

    fn fail<T>(&self, what: &str) -> Result<T, String> {
        Err(format!("JSON: {what} at byte {}", self.at))
    }

    fn eat(&mut self, word: &str, v: Json) -> Result<Json, String> {
        if self.s[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(v)
        } else {
            self.fail("unknown word")
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.space();
        match self.s.get(self.at) {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => self.string().map(Json::Str),
            Some(b't') => self.eat("true", Json::Bool(true)),
            Some(b'f') => self.eat("false", Json::Bool(false)),
            Some(b'n') => self.eat("null", Json::Null),
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.number(),
            _ => self.fail("expected a value"),
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.at += 1;
        let mut members = Vec::new();
        self.space();
        if self.s.get(self.at) == Some(&b'}') {
            self.at += 1;
            return Ok(Json::Obj(members));
        }
        loop {
            self.space();
            if self.s.get(self.at) != Some(&b'"') {
                return self.fail("expected a key");
            }
            let k = self.string()?;
            self.space();
            if self.s.get(self.at) != Some(&b':') {
                return self.fail("expected ':'");
            }
            self.at += 1;
            members.push((k, self.value()?));
            self.space();
            match self.s.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Obj(members));
                }
                _ => return self.fail("expected ',' or '}'"),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.at += 1;
        let mut items = Vec::new();
        self.space();
        if self.s.get(self.at) == Some(&b']') {
            self.at += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value()?);
            self.space();
            match self.s.get(self.at) {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return self.fail("expected ',' or ']'"),
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.at;
        while self.s.get(self.at).is_some_and(|c| b"+-.eE0123456789".contains(c)) {
            self.at += 1;
        }
        std::str::from_utf8(&self.s[start..self.at])
            .ok()
            .and_then(|t| t.parse().ok())
            .map(Json::Num)
            .ok_or_else(|| format!("JSON: bad number at byte {start}"))
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let t = self.s.get(self.at..self.at + 4).ok_or("JSON: short \\u escape")?;
        self.at += 4;
        std::str::from_utf8(t)
            .ok()
            .and_then(|t| u32::from_str_radix(t, 16).ok())
            .ok_or_else(|| "JSON: bad \\u escape".to_string())
    }

    fn string(&mut self) -> Result<String, String> {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let Some(&c) = self.s.get(self.at) else { return self.fail("unended string") };
            self.at += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let Some(&e) = self.s.get(self.at) else { return self.fail("unended escape") };
                    self.at += 1;
                    let ch = match e {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut u = self.hex4()?;
                            // A surrogate pair: the second half follows.
                            if (0xd800..0xdc00).contains(&u)
                                && self.s[self.at..].starts_with(b"\\u")
                            {
                                self.at += 2;
                                let low = self.hex4()?;
                                u = 0x10000
                                    + ((u - 0xd800) << 10)
                                    + (low.wrapping_sub(0xdc00) & 0x3ff);
                            }
                            char::from_u32(u).unwrap_or('\u{fffd}')
                        }
                        _ => return self.fail("bad escape"),
                    };
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                }
                _ => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| "JSON: a string is not UTF-8".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_nest_and_strings_unescape() {
        let v = Json::parse(r#" {"a": [1, -2.5e1, true, null], "b": {"c": "x\"é😀\n"}, "d": []} "#)
            .unwrap();
        assert_eq!(
            v.get("a").unwrap().arr(),
            [Json::Num(1.0), Json::Num(-25.0), Json::Bool(true), Json::Null]
        );
        assert_eq!(v.get("b").and_then(|b| b.get("c")).and_then(Json::str), Some("x\"é😀\n"));
        assert!(v.get("d").unwrap().arr().is_empty());
        assert!(v.get("e").is_none());
    }

    #[test]
    fn bad_text_is_refused() {
        for t in ["", "{", "[1,]", "{\"a\" 1}", "tru", "\"x", "1 2"] {
            assert!(Json::parse(t).is_err(), "{t}");
        }
    }
}
