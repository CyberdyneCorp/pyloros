use super::IncomparableTimestamps;
use chrono::{Datelike, NaiveDate, Weekday};
use std::cmp::Ordering;

pub(super) fn compare(
    actual: Option<&str>,
    expected: &str,
) -> Result<Option<Ordering>, IncomparableTimestamps> {
    let Some(((a, zone_a), (b, zone_b))) = actual.and_then(parse).zip(parse(expected)) else {
        return Ok(None);
    };
    if zone_a != zone_b {
        return Err(IncomparableTimestamps);
    }
    Ok(Some(a.cmp(&b)))
}

fn digits(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

fn date(raw: &str) -> Option<NaiveDate> {
    let year = digits(raw.get(..4)?)? as i32;
    if year == 0 {
        return None;
    }
    let tail = raw.get(4..)?;
    let extended = tail.starts_with('-');
    let tail = tail.strip_prefix('-').unwrap_or(tail);
    if let Some(week) = tail.strip_prefix('W') {
        let num = digits(week.get(..2)?)?;
        let day = match week.get(2..)? {
            "" => 1,
            extra => {
                let d = if extended {
                    extra.strip_prefix('-')?
                } else {
                    extra
                };
                if d.len() != 1 {
                    return None;
                }
                digits(d)?
            }
        };
        let weekday = Weekday::try_from(day.checked_sub(1)? as u8).ok()?;
        return NaiveDate::from_isoywd_opt(year, num, weekday)
            .filter(|d| (1..=9999).contains(&d.year()));
    }
    let month = digits(tail.get(..2)?)?;
    let rest = tail.get(2..)?;
    let day = if extended {
        rest.strip_prefix('-')?
    } else {
        rest
    };
    if day.len() != 2 {
        return None;
    }
    NaiveDate::from_ymd_opt(year, month, digits(day)?)
}

fn components(whole: &str) -> Option<Vec<u32>> {
    if whole.len() > 8 {
        return None;
    }
    if whole.contains(':') {
        return whole.split(':').map(pair).collect();
    }
    whole
        .as_bytes()
        .chunks(2)
        .map(|b| pair(std::str::from_utf8(b).ok()?))
        .collect()
}

fn pair(s: &str) -> Option<u32> {
    (s.len() == 2).then(|| digits(s)).flatten()
}

fn clock(raw: &str, offset: bool) -> Option<i64> {
    let (whole, fraction) = raw
        .split_once(['.', ','])
        .map_or((raw, None), |(a, b)| (a, Some(b)));
    let parts = components(whole)?;
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let (h, m, s) = (
        parts[0],
        *parts.get(1).unwrap_or(&0),
        *parts.get(2).unwrap_or(&0),
    );
    if !offset && (h > 24 || m > 59 || s > 59) {
        return None;
    }
    let seconds = i64::from(h * 3600 + m * 60 + s);
    let micros = match fraction {
        Some(f) if parts.len() == 3 => fractional_micros(f)?,
        Some(_) => return None,
        None => 0,
    };
    if !offset && h == 24 && (m != 0 || s != 0 || micros != 0) {
        return None;
    }
    if offset && seconds == 0 {
        return Some(0);
    }
    Some(seconds * 1_000_000 + micros)
}

fn fractional_micros(raw: &str) -> Option<i64> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let len = raw.len().min(6);
    Some(i64::from(digits(&raw[..len])? * 10u32.pow(6 - len as u32)))
}

fn parse(raw: &str) -> Option<(i64, bool)> {
    let len = date_length(raw);
    let d = date(raw.get(..len)?)?;
    let midnight = d.and_hms_opt(0, 0, 0)?.and_utc().timestamp_micros();
    let tail = &raw[len..];
    if tail.is_empty() {
        return Some((midnight, false));
    }
    let time = tail.get(tail.chars().next()?.len_utf8()..)?;
    let split = time.find(['Z', '+', '-']).unwrap_or(time.len());
    let zone = &time[split..];
    let local = local_time(&time[..split], !zone.is_empty())?;
    if local == 86_400_000_000 && d.year() == 9999 && d.ordinal() == 365 {
        return None;
    }
    Some((midnight + local - zone_shift(zone)?, !zone.is_empty()))
}

// Distinguish a weekday from a numeric separator before a compact clock.
fn date_length(raw: &str) -> usize {
    let b = raw.as_bytes();
    if b.get(4) == Some(&b'W') {
        let run = b[7.min(b.len())..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();
        return if run == 1 || run > 0 && run % 2 == 0 {
            8
        } else {
            7
        };
    }
    if raw.get(4..6) == Some("-W") {
        return if b.get(8) == Some(&b'-') && !b.get(10).is_some_and(u8::is_ascii_digit) {
            10
        } else {
            8
        };
    }
    if b.get(4) == Some(&b'-') { 10 } else { 8 }
}

fn zone_shift(zone: &str) -> Option<i64> {
    match zone {
        "" | "Z" => Some(0),
        _ if zone.starts_with(['+', '-']) => {
            let offset = clock(&zone[1..], true)?;
            if offset >= 86_400_000_000 {
                return None;
            }
            Some(if zone.starts_with('-') {
                -offset
            } else {
                offset
            })
        }
        _ => None,
    }
}

fn local_time(raw: &str, has_offset: bool) -> Option<i64> {
    clock(raw, false).or_else(|| {
        // A zone designator also terminates the last two-digit time component.
        if !has_offset {
            return None;
        }
        let (prefix, _) = raw.split_at_checked(raw.len().checked_sub(1)?)?;
        if prefix.contains(['.', ',']) {
            return None;
        }
        clock(prefix, false)
    })
}
