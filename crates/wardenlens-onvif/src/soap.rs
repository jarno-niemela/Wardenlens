//! Bounded reading of an untrusted SOAP reply into a small arena of elements.
//!
//! One pass over quick-xml events, no recursion: the element stack is a counter and the tree is a
//! flat `Vec` of at most [`MAX_ELEMENTS`] entries nested at most [`MAX_DEPTH`] deep. DOCTYPE is
//! refused, so no entity is ever defined; the five predefined entities and character references
//! are resolved here, nothing else, so nothing can expand. Namespace prefixes are stripped and
//! namespace URIs are not checked: the camera is only trusted to the extent that every value
//! read from the tree is validated afterwards (SEC-2).
//!
//! The same limits style as the `AgentDVR` importer: typed errors, a position only, no text.

use std::borrow::Cow;

use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::{MAX_BODY_BYTES, MAX_DEPTH, MAX_ELEMENTS, OnvifError};

/// Longest element text that is kept, in bytes. A longer one is flagged, not stored in full.
pub(crate) const MAX_TEXT_BYTES: usize = 4096;
/// Longest `token` attribute that is kept, in bytes.
const MAX_ATTR_BYTES: usize = 256;

/// One element of the reply.
pub(crate) struct Elem {
    /// Local name (prefix removed).
    pub name: String,
    pub parent: Option<usize>,
    /// The `token` attribute, if any (cut at [`MAX_ATTR_BYTES`] and flagged by `token_too_long`).
    pub token: Option<String>,
    pub token_too_long: bool,
    /// Direct text and CDATA, concatenated (cut at [`MAX_TEXT_BYTES`]).
    pub text: String,
    pub text_too_long: bool,
}

/// A parsed reply: element 0 is the root.
pub(crate) struct Doc {
    elems: Vec<Elem>,
}

/// A character XML 1.0 allows (production `Char`).
fn is_xml_char(c: char) -> bool {
    matches!(u32::from(c), 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x1_0000..=0x10_FFFF)
}

impl Doc {
    /// Reads `bytes`, applying every limit.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, OnvifError> {
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Err(OnvifError::EmptyReply);
        }
        if bytes.len() > MAX_BODY_BYTES {
            return Err(OnvifError::BodyTooLarge);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| OnvifError::NotUtf8)?;
        let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
        read(text)
    }

    pub(crate) fn elem(&self, idx: usize) -> Option<&Elem> {
        self.elems.get(idx)
    }

    /// Direct children of `idx` in document order.
    pub(crate) fn children(&self, idx: usize) -> impl Iterator<Item = usize> + '_ {
        self.elems
            .iter()
            .enumerate()
            .filter(move |(_, e)| e.parent == Some(idx))
            .map(|(i, _)| i)
    }

    /// The first direct child of `idx` called `name`.
    pub(crate) fn child(&self, idx: usize, name: &str) -> Option<usize> {
        self.children(idx)
            .find(|i| self.elem(*i).is_some_and(|e| e.name == name))
    }

    /// The first child of `idx` found by following `names` one level at a time.
    pub(crate) fn path(&self, idx: usize, names: &[&str]) -> Option<usize> {
        names.iter().try_fold(idx, |at, n| self.child(at, n))
    }

    /// `idx` and everything below it, in document order.
    fn subtree(&self, idx: usize) -> Vec<usize> {
        let mut inside = vec![false; self.elems.len()];
        let mut found = Vec::new();
        // Parents always precede their children, so one forward pass finds every descendant.
        for (i, e) in self.elems.iter().enumerate().skip(idx) {
            let member = i == idx || e.parent.is_some_and(|p| inside.get(p) == Some(&true));
            if member {
                if let Some(slot) = inside.get_mut(i) {
                    *slot = true;
                }
                found.push(i);
            }
        }
        found
    }

    /// The element of the response called `response`, or the error the reply stands for: a fault,
    /// or a reply that is not the expected SOAP envelope.
    pub(crate) fn response(&self, response: &'static str) -> Result<usize, OnvifError> {
        let root = self.elem(0).ok_or(OnvifError::MissingElement {
            element: "Envelope",
        })?;
        if root.name != "Envelope" {
            return Err(OnvifError::MissingElement {
                element: "Envelope",
            });
        }
        let body = self
            .child(0, "Body")
            .ok_or(OnvifError::MissingElement { element: "Body" })?;
        if let Some(fault) = self.child(body, "Fault") {
            return Err(self.classify_fault(fault));
        }
        self.child(body, response)
            .ok_or(OnvifError::MissingElement { element: response })
    }

    /// `NotAuthorized` when a `Value` inside the fault names `ter:NotAuthorized`, else `SoapFault`.
    /// Only a fixed code is recognised; no fault text is kept.
    fn classify_fault(&self, fault: usize) -> OnvifError {
        let refused = self.subtree(fault).into_iter().any(|i| {
            self.elem(i).is_some_and(|e| {
                e.name == "Value" && e.text.trim().rsplit(':').next() == Some("NotAuthorized")
            })
        });
        if refused {
            OnvifError::NotAuthorized
        } else {
            OnvifError::SoapFault
        }
    }
}

struct Builder {
    elems: Vec<Elem>,
    /// Indices of the open elements, innermost last.
    open: Vec<usize>,
    root_done: bool,
}

impl Builder {
    fn start(&mut self, e: &BytesStart<'_>) -> Result<Result<(), OnvifError>, ()> {
        if self.open.is_empty() && self.root_done {
            return Err(());
        }
        if self.open.len() >= MAX_DEPTH {
            return Ok(Err(OnvifError::TooDeep));
        }
        if self.elems.len() >= MAX_ELEMENTS {
            return Ok(Err(OnvifError::TooManyElements));
        }
        let mut token = None;
        let mut token_too_long = false;
        for attr in e.attributes() {
            let attr = attr.map_err(|_| ())?;
            // `<` is never legal in an attribute value, whichever attribute it is.
            if attr.value.contains('<') {
                return Err(());
            }
            let v = value_of(&attr)?;
            if attr.key.as_ref() == "token" {
                if v.len() > MAX_ATTR_BYTES {
                    token_too_long = true;
                } else {
                    token = Some(v.into_owned());
                }
            }
        }
        let name = e.local_name();
        self.elems.push(Elem {
            name: name.as_ref().to_owned(),
            parent: self.open.last().copied(),
            token,
            token_too_long,
            text: String::new(),
            text_too_long: false,
        });
        self.open.push(self.elems.len().saturating_sub(1));
        Ok(Ok(()))
    }

    fn end(&mut self) {
        self.open.pop();
        if self.open.is_empty() {
            self.root_done = true;
        }
    }

    fn push_text(&mut self, piece: &str) {
        let Some(e) = self.open.last().and_then(|i| self.elems.get_mut(*i)) else {
            return;
        };
        if e.text.len().saturating_add(piece.len()) > MAX_TEXT_BYTES {
            e.text_too_long = true;
        } else {
            e.text.push_str(piece);
        }
    }
}

/// The attribute value with entities resolved and line breaks normalised. A character XML does
/// not allow is malformed.
fn value_of<'a>(attr: &quick_xml::events::attributes::Attribute<'a>) -> Result<Cow<'a, str>, ()> {
    let v = attr
        .normalized_value(XmlVersion::Implicit1_0)
        .map_err(|_| ())?;
    if v.chars().all(is_xml_char) {
        Ok(v)
    } else {
        Err(())
    }
}

fn read(text: &str) -> Result<Doc, OnvifError> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;
    let mut b = Builder {
        elems: Vec::new(),
        open: Vec::new(),
        root_done: false,
    };
    let mut at_start = true;
    loop {
        let malformed = |r: &Reader<&[u8]>| OnvifError::Malformed {
            position: r.error_position(),
        };
        let Ok(event) = reader.read_event() else {
            return Err(malformed(&reader));
        };
        let was_at_start = at_start;
        at_start = at_start && matches!(event, Event::Text(_));
        match event {
            Event::Start(e) => match b.start(&e) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(()) => return Err(malformed(&reader)),
            },
            Event::End(_) => b.end(),
            Event::Text(t) => {
                let s = t.xml10_content();
                if b.open.is_empty() && !s.trim().is_empty() {
                    return Err(malformed(&reader));
                }
                if !s.chars().all(is_xml_char) {
                    return Err(malformed(&reader));
                }
                b.push_text(&s);
            }
            Event::CData(c) => {
                if b.open.is_empty() {
                    return Err(malformed(&reader));
                }
                b.push_text(&c.xml10_content());
            }
            Event::GeneralRef(r) => {
                if b.open.is_empty() {
                    return Err(malformed(&reader));
                }
                let mut buf = [0_u8; 4];
                let resolved: Option<&str> = match r.resolve_char_ref() {
                    Ok(Some(c)) if is_xml_char(c) => Some(c.encode_utf8(&mut buf)),
                    Ok(Some(_)) | Err(_) => None,
                    Ok(None) => resolve_predefined_entity(&r),
                };
                match resolved {
                    Some(s) => b.push_text(s),
                    None => return Err(malformed(&reader)),
                }
            }
            Event::Decl(d) => {
                if !was_at_start {
                    return Err(malformed(&reader));
                }
                if let Some(enc) = d.encoding() {
                    match enc {
                        Ok(v) if v.eq_ignore_ascii_case("utf-8") => {}
                        Ok(_) => return Err(OnvifError::UnsupportedEncoding),
                        Err(_) => return Err(malformed(&reader)),
                    }
                }
            }
            Event::DocType(_) => return Err(OnvifError::DocType),
            Event::Comment(_) | Event::PI(_) | Event::Empty(_) => {}
            Event::Eof => {
                if !b.open.is_empty() || b.elems.is_empty() {
                    return Err(malformed(&reader));
                }
                return Ok(Doc { elems: b.elems });
            }
        }
    }
}
