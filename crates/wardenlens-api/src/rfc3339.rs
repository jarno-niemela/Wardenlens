//! A strict RFC 3339 timestamp parser for the `from` and `to` query parameters.
//!
//! Pass-list grammar, nothing else is accepted:
//! `YYYY-MM-DD` `T`|`t` `HH:MM:SS` [`.` 1 to 9 digits] (`Z`|`z`|(`+`|`-`)`HH:MM`).
//! The date must exist (leap years included), the hour is 0 to 23, the minute and the offset
//! minute 0 to 59, the second 0 to 59 (a leap second `:60` is refused) and the offset hour 0 to
//! 23. Fractions beyond milliseconds are truncated. The result is UTC Unix milliseconds. The
//! input is checked to be ASCII before any indexing, so a multibyte character is a plain refusal.

use wardenlens_core::time::Timestamp;

/// Longest accepted text: `YYYY-MM-DDTHH:MM:SS.fffffffff+HH:MM`.
const MAX_LEN: usize = 35;

/// Parses `text`; `None` for anything that is not a valid RFC 3339 timestamp.
pub(crate) fn parse(text: &str) -> Option<Timestamp> {
    if !text.is_ascii() || text.len() > MAX_LEN {
        return None;
    }
    let b = text.as_bytes();
    let year = num(b.get(0..4)?)?;
    expect(b, 4, b'-')?;
    let month = num(b.get(5..7)?)?;
    expect(b, 7, b'-')?;
    let day = num(b.get(8..10)?)?;
    if !matches!(b.get(10)?, b'T' | b't') {
        return None;
    }
    let hour = num(b.get(11..13)?)?;
    expect(b, 13, b':')?;
    let minute = num(b.get(14..16)?)?;
    expect(b, 16, b':')?;
    let second = num(b.get(17..19)?)?;
    let mut at = 19;
    let mut millis: i64 = 0;
    if b.get(at) == Some(&b'.') {
        at = at.checked_add(1)?;
        let start = at;
        while b.get(at).is_some_and(u8::is_ascii_digit) {
            at = at.checked_add(1)?;
        }
        let digits = b.get(start..at)?;
        if digits.is_empty() || digits.len() > 9 {
            return None;
        }
        // The first three digits are the milliseconds; the rest is truncated.
        let mut scale: i64 = 100;
        for d in digits.iter().take(3) {
            millis = millis.checked_add(i64::from(d.checked_sub(b'0')?).checked_mul(scale)?)?;
            scale /= 10;
        }
    }
    let offset_secs: i64 = match b.get(at)? {
        b'Z' | b'z' => {
            at = at.checked_add(1)?;
            0
        }
        sign @ (b'+' | b'-') => {
            let oh = num(b.get(at.checked_add(1)?..at.checked_add(3)?)?)?;
            expect(b, at.checked_add(3)?, b':')?;
            let om = num(b.get(at.checked_add(4)?..at.checked_add(6)?)?)?;
            at = at.checked_add(6)?;
            if oh > 23 || om > 59 {
                return None;
            }
            let magnitude = i64::from(oh)
                .checked_mul(3600)?
                .checked_add(i64::from(om).checked_mul(60)?)?;
            if *sign == b'-' {
                magnitude.checked_neg()?
            } else {
                magnitude
            }
        }
        _ => return None,
    };
    if at != b.len() {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 || !(1..=12).contains(&month) {
        return None;
    }
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let days = days_from_civil(i64::from(year), i64::from(month), i64::from(day))?;
    let time_of_day = i64::from(hour)
        .checked_mul(3600)?
        .checked_add(i64::from(minute).checked_mul(60)?)?
        .checked_add(i64::from(second))?;
    let secs = days
        .checked_mul(86_400)?
        .checked_add(time_of_day)?
        .checked_sub(offset_secs)?;
    Some(Timestamp::from_unix_millis(
        secs.checked_mul(1000)?.checked_add(millis)?,
    ))
}

fn expect(b: &[u8], at: usize, c: u8) -> Option<()> {
    (b.get(at) == Some(&c)).then_some(())
}

/// A fixed-width run of ASCII digits.
fn num(digits: &[u8]) -> Option<u32> {
    let mut n: u32 = 0;
    for d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        n = n
            .checked_mul(10)?
            .checked_add(u32::from(d.checked_sub(b'0')?))?;
    }
    Some(n)
}

fn is_leap(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 of a valid civil date (Howard Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> Option<i64> {
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y.div_euclid(400);
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(d.checked_sub(1)?)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe.checked_div(4)?)?
        .checked_sub(yoe.checked_div(100)?)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(s: &str) -> Option<i64> {
        parse(s).map(Timestamp::as_unix_millis)
    }

    #[test]
    fn known_instants() {
        assert_eq!(ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(ms("1970-01-01T00:00:00.001Z"), Some(1));
        assert_eq!(ms("2000-02-29T12:34:56Z"), Some(951_827_696_000));
        assert_eq!(ms("2024-01-01T00:00:00Z"), Some(1_704_067_200_000));
        assert_eq!(ms("1969-12-31T23:59:59.999Z"), Some(-1));
        assert_eq!(ms("0000-01-01T00:00:00Z"), Some(-62_167_219_200_000));
        assert_eq!(ms("9999-12-31T23:59:59Z"), Some(253_402_300_799_000));
    }

    #[test]
    fn offsets_and_case() {
        assert_eq!(ms("2024-01-01T02:00:00+02:00"), ms("2024-01-01T00:00:00Z"));
        assert_eq!(ms("2023-12-31T22:00:00-02:00"), ms("2024-01-01T00:00:00Z"));
        assert_eq!(ms("2024-01-01t00:00:00z"), ms("2024-01-01T00:00:00Z"));
        assert_eq!(ms("2024-01-01T00:00:00-00:00"), ms("2024-01-01T00:00:00Z"));
    }

    #[test]
    fn fractions_truncate_to_milliseconds() {
        assert_eq!(
            ms("2024-01-01T00:00:00.123456789Z"),
            Some(1_704_067_200_123)
        );
        assert_eq!(ms("2024-01-01T00:00:00.9Z"), Some(1_704_067_200_900));
        assert_eq!(ms("2024-01-01T00:00:00.12Z"), Some(1_704_067_200_120));
    }

    #[test]
    fn refuses_everything_off_grammar() {
        let bad = [
            "",
            "2024-01-01",
            "2024-01-01T00:00:00",
            "2024-01-01 00:00:00Z",
            "2024-01-01T00:00:00 02:00",
            "2024-01-01T00:00:00+0200",
            "2024-01-01T00:00:00+02",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00.1234567890Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01T24:00:00Z",
            "2024-01-01T00:60:00Z",
            "2024-13-01T00:00:00Z",
            "2024-00-01T00:00:00Z",
            "2024-01-00T00:00:00Z",
            "2024-01-32T00:00:00Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2024-04-31T00:00:00Z",
            "2024-01-01T00:00:00+24:00",
            "2024-01-01T00:00:00+00:60",
            "2024-01-01T00:00:00Zjunk",
            "2024-01-01T00:00:00Z ",
            " 2024-01-01T00:00:00Z",
            "+2024-01-01T00:00:00Z",
            "2024-01-01T00:00:+1Z",
            "-024-01-01T00:00:00Z",
            "2024-01-01T00:00:00\u{e9}",
            "2024-01-01T00:00:00.\u{e9}Z",
            "\u{e9}024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z\0",
            "20240101T000000Z",
        ];
        for s in bad {
            assert_eq!(parse(s), None, "{s:?}");
        }
    }

    #[test]
    fn leap_years() {
        assert!(parse("2000-02-29T00:00:00Z").is_some());
        assert!(parse("2024-02-29T00:00:00Z").is_some());
        assert!(parse("2100-02-29T00:00:00Z").is_none());
    }

    #[test]
    fn every_prefix_and_multibyte_splice_is_refused_without_panic() {
        let good = "2024-01-01T00:00:00.123+02:00";
        for n in 0..good.len() {
            assert_eq!(parse(&good[..n]), None, "prefix {n}");
        }
        for i in 0..=good.len() {
            let mut s = good.to_owned();
            s.insert(i, '\u{e9}');
            assert_eq!(parse(&s), None, "splice at {i}");
        }
    }
}
