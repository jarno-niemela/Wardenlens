//! The XML walk: events in, [`RawCamera`] out, with every limit enforced as it goes.
//!
//! One pass over quick-xml events, no recursion and no tree: the element stack is a `Vec` of at
//! most [`MAX_DEPTH`] small enums. DOCTYPE is refused, so no entity is ever defined; entity
//! references are resolved here (the five predefined ones and numeric character references,
//! nothing else), so nothing can expand. Only text inside `videosourcestring`, `login` and
//! `password` under `objects/cameras/camera/settings` is kept in the entry; the text of those
//! three, at any depth below them, is also collected whole for the logins (see `Logins`).

use std::borrow::Cow;

use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use secrecy::zeroize::Zeroizing;

use crate::{ImportError, Logins, MAX_CAMERAS, MAX_DEPTH, MAX_FIELD_BYTES};

/// One text field of `settings`, with what is needed to tell a repeat or an over-long value.
#[derive(Default)]
pub(crate) struct Slot {
    pub text: Option<Zeroizing<String>>,
    pub count: u8,
    pub too_long: bool,
}

/// One `camera` element, as read. Nothing here is validated yet.
#[derive(Default)]
pub(crate) struct RawCamera {
    pub position: usize,
    pub agent_id: Option<u32>,
    pub name: Option<String>,
    pub deleted: bool,
    pub settings_count: u8,
    pub source: Slot,
    pub login: Slot,
    pub password: Slot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Source,
    Login,
    Password,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Node {
    Root,
    Cameras,
    Camera,
    Settings,
    Field(Field),
    Other,
}

/// What an element named `name` is, as a child of `parent`.
fn child(parent: Node, name: &str) -> Node {
    match (parent, name) {
        (Node::Root, "cameras") => Node::Cameras,
        (Node::Cameras, "camera") => Node::Camera,
        (Node::Camera, "settings") => Node::Settings,
        (Node::Settings, "videosourcestring") => Node::Field(Field::Source),
        (Node::Settings, "login") => Node::Field(Field::Login),
        (Node::Settings, "password") => Node::Field(Field::Password),
        _ => Node::Other,
    }
}

/// A character XML 1.0 allows (production `Char`).
fn is_xml_char(c: char) -> bool {
    matches!(u32::from(c), 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x1_0000..=0x10_FFFF)
}

struct Walker {
    stack: Vec<Node>,
    cameras: Vec<RawCamera>,
    camera_count: usize,
    logins: Logins,
    text: Zeroizing<String>,
    text_too_long: bool,
    /// Every text piece of the field being read, any depth below it, bounded only by the input.
    /// Independent of `MAX_FIELD_BYTES`: the logins of a field the camera entry rejects as too
    /// long must still be known.
    /// `Some` between the start and the end of one of the three fields.
    collect: Option<Zeroizing<String>>,
    root_seen: bool,
    root_done: bool,
}

impl Walker {
    fn new() -> Self {
        Self {
            stack: Vec::new(),
            cameras: Vec::new(),
            camera_count: 0,
            logins: Logins::default(),
            text: Zeroizing::default(),
            text_too_long: false,
            collect: None,
            root_seen: false,
            root_done: false,
        }
    }

    fn current_camera(&mut self) -> Option<&mut RawCamera> {
        self.cameras.last_mut()
    }

    /// `Err(())` means malformed; the caller attaches the position.
    fn start(&mut self, e: &BytesStart<'_>) -> Result<Result<(), ImportError>, ()> {
        let name = e.name();
        let name = name.as_ref();
        let node = match self.stack.last() {
            None => {
                if self.root_done {
                    return Err(());
                }
                if name != "objects" {
                    return Ok(Err(ImportError::NotObjects));
                }
                self.root_seen = true;
                Node::Root
            }
            Some(parent) => child(*parent, name),
        };
        if self.stack.len() >= MAX_DEPTH {
            return Ok(Err(ImportError::TooDeep));
        }
        // Every start tag is checked for duplicate or broken attributes, as `camera` needs them.
        let mut camera = None;
        if node == Node::Camera {
            if self.camera_count >= MAX_CAMERAS {
                return Ok(Err(ImportError::TooManyCameras));
            }
            camera = Some(RawCamera {
                position: self.camera_count,
                ..RawCamera::default()
            });
            self.camera_count = self.camera_count.saturating_add(1);
        }
        for attr in e.attributes() {
            let attr = attr.map_err(|_| ())?;
            // `<` is never legal in an attribute value, whichever attribute it is.
            if attr.value.contains('<') {
                return Err(());
            }
            // Every attribute value is resolved, so a bad entity is refused wherever it is.
            let v = value_of(&attr)?;
            if let Some(c) = camera.as_mut() {
                let key = attr.key;
                match key.as_ref() {
                    "id" => {
                        c.agent_id = v.parse::<u32>().ok();
                    }
                    "name" => {
                        c.name = Some(v.into_owned());
                    }
                    "deleted" => {
                        c.deleted = v.eq_ignore_ascii_case("true") || v == "1";
                    }
                    _ => {}
                }
            }
        }
        match node {
            Node::Settings => {
                if let Some(c) = camera_of(&mut self.cameras) {
                    c.settings_count = c.settings_count.saturating_add(1);
                }
            }
            Node::Field(f) => {
                if let Some(c) = camera_of(&mut self.cameras) {
                    let slot = slot_of(c, f);
                    slot.count = slot.count.saturating_add(1);
                }
                self.text = Zeroizing::default();
                self.text_too_long = false;
                self.collect = Some(Zeroizing::default());
            }
            _ => {}
        }
        if let Some(c) = camera {
            self.cameras.push(c);
        }
        self.stack.push(node);
        Ok(Ok(()))
    }

    fn end(&mut self) -> Result<(), ImportError> {
        let Some(node) = self.stack.pop() else {
            return Ok(());
        };
        if let Node::Field(f) = node {
            let text = std::mem::take(&mut self.text);
            let too_long = std::mem::take(&mut self.text_too_long);
            let collected = self.collect.take().unwrap_or_default();
            // Every occurrence, before the slot keeps only one: a repeated element is skipped
            // later, but its text must still be known. The whole text, not the truncated slot.
            match f {
                Field::Source => self.logins.add_source(&collected)?,
                Field::Login | Field::Password => self.logins.add_field(&collected)?,
            }
            if let Some(c) = self.current_camera() {
                let slot = slot_of(c, f);
                slot.too_long |= too_long;
                slot.text = Some(text);
            }
        }
        if self.stack.is_empty() {
            self.root_done = true;
        }
        Ok(())
    }

    fn push_text(&mut self, piece: &str) {
        if let Some(collect) = self.collect.as_mut() {
            push_zeroizing(collect, piece);
        }
        if self
            .stack
            .last()
            .is_some_and(|n| matches!(n, Node::Field(_)))
        {
            if self.text.len().saturating_add(piece.len()) > MAX_FIELD_BYTES {
                self.text_too_long = true;
            } else {
                self.text.push_str(piece);
            }
        }
    }
}

/// Appends to a secret buffer without leaving an unzeroised copy behind when it grows: the old
/// buffer is a `Zeroizing` that is wiped on drop, where a plain `String` would free it as is.
fn push_zeroizing(buf: &mut Zeroizing<String>, piece: &str) {
    let needed = buf.len().saturating_add(piece.len());
    if needed > buf.capacity() {
        let capacity = needed.max(buf.capacity().saturating_mul(2)).max(64);
        let mut bigger = Zeroizing::new(String::with_capacity(capacity));
        bigger.push_str(buf);
        *buf = bigger;
    }
    buf.push_str(piece);
}

/// The attribute value with entities resolved (the five predefined ones and character
/// references) and line breaks normalised. A character XML does not allow is malformed.
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

fn camera_of(cameras: &mut [RawCamera]) -> Option<&mut RawCamera> {
    cameras.last_mut()
}

fn slot_of(c: &mut RawCamera, f: Field) -> &mut Slot {
    match f {
        Field::Source => &mut c.source,
        Field::Login => &mut c.login,
        Field::Password => &mut c.password,
    }
}

/// Reads the cameras of `text` (UTF-8, BOM already removed).
pub(crate) fn read(text: &str) -> Result<(Vec<RawCamera>, Logins), ImportError> {
    let mut reader = Reader::from_str(text);
    reader.config_mut().expand_empty_elements = true;
    let mut w = Walker::new();
    let mut at_start = true;
    loop {
        let malformed = |r: &Reader<&[u8]>| ImportError::Malformed {
            position: r.error_position(),
        };
        let Ok(event) = reader.read_event() else {
            return Err(malformed(&reader));
        };
        let was_at_start = at_start;
        at_start = at_start && matches!(event, Event::Text(_));
        let at_start_for_event = was_at_start;
        match event {
            Event::Start(e) => match w.start(&e) {
                Ok(Ok(())) => {}
                Ok(Err(e)) => return Err(e),
                Err(()) => return Err(malformed(&reader)),
            },
            Event::End(_) => w.end()?,
            Event::Text(t) => {
                let s = t.xml10_content();
                if w.stack.is_empty() && !s.trim().is_empty() {
                    return Err(malformed(&reader));
                }
                w.push_text(&s);
            }
            Event::CData(c) => {
                if w.stack.is_empty() {
                    return Err(malformed(&reader));
                }
                w.push_text(&c.xml10_content());
            }
            Event::GeneralRef(r) => {
                if w.stack.is_empty() {
                    return Err(malformed(&reader));
                }
                let mut buf = [0_u8; 4];
                let resolved: Option<&str> = match r.resolve_char_ref() {
                    Ok(Some(c)) if is_xml_char(c) => Some(c.encode_utf8(&mut buf)),
                    Ok(Some(_)) | Err(_) => None,
                    Ok(None) => resolve_predefined_entity(&r),
                };
                match resolved {
                    Some(s) => w.push_text(s),
                    None => return Err(malformed(&reader)),
                }
            }
            Event::Decl(d) => {
                // Only as the first thing in the document (white space may precede it here);
                // a second or a mid-document declaration is malformed, never an encoding error.
                if !at_start_for_event {
                    return Err(malformed(&reader));
                }
                if let Some(enc) = d.encoding() {
                    match enc {
                        Ok(v) if v.eq_ignore_ascii_case("utf-8") => {}
                        Ok(_) => return Err(ImportError::UnsupportedEncoding),
                        Err(_) => return Err(malformed(&reader)),
                    }
                }
            }
            Event::DocType(_) => return Err(ImportError::DocType),
            Event::Comment(_) | Event::PI(_) | Event::Empty(_) => {}
            Event::Eof => {
                if !w.stack.is_empty() {
                    return Err(malformed(&reader));
                }
                if !w.root_seen {
                    return Err(ImportError::NotObjects);
                }
                return Ok((w.cameras, w.logins));
            }
        }
    }
}
