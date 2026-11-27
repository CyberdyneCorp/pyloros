//! Cursor timestamps identify a civil time. Their optional offset is validated
//! and discarded before comparing against the stored UTC event time.
use chrono::{Datelike, NaiveDate, NaiveDateTime, NaiveTime, Weekday};

pub(super) fn parse(text: &str) -> Option<NaiveDateTime> {
    let (mut date, tail) = date(text)?;
    if tail.is_empty() {
        return Some(date.and_time(NaiveTime::MIN));
    }
    let time = &tail[tail.chars().next()?.len_utf8()..];
    let wall = if let Some(t) = time.strip_suffix('Z') {
        t
    } else if let Some(i) = time.find(['+', '-']) {
        let (h, m, s, _) = clock(&time[i + 1..])?;
        if h * 3600 + m * 60 + s >= 86400 {
            return None;
        }
        &time[..i]
    } else {
        time
    };
    let (mut h, m, s, us) = clock(wall)?;
    if (h, m, s, us) == (24, 0, 0, 0) {
        date = date.succ_opt().filter(|d| d.year() <= 9999)?;
        h = 0;
    }
    date.and_hms_micro_opt(h, m, s, us)
}

fn number(text: &str) -> Option<u32> {
    text.bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| text.parse().ok())
        .flatten()
}

fn date(text: &str) -> Option<(NaiveDate, &str)> {
    let year = number(text.get(..4)?)? as i32;
    if year == 0 {
        return None;
    }
    let tail = text.get(4..)?;
    let extended = tail.starts_with('-');
    let sep = if extended { "-" } else { "" };
    let rest = tail.strip_prefix(sep)?;
    if let Some(week) = rest.strip_prefix('W') {
        let n = number(week.get(..2)?)?;
        let tail = week.get(2..)?;
        let weekday = tail
            .strip_prefix(sep)
            .and_then(|v| v.get(..1))
            .and_then(number);
        let (day, tail) = match weekday {
            Some(d) => (
                Weekday::try_from(u8::try_from(d.checked_sub(1)?).ok()?).ok()?,
                &tail[sep.len() + 1..],
            ),
            None => (Weekday::Mon, tail),
        };
        return Some((NaiveDate::from_isoywd_opt(year, n, day)?, tail));
    }
    let month = number(rest.get(..2)?)?;
    let day = rest.get(2..)?.strip_prefix(sep)?;
    Some((
        NaiveDate::from_ymd_opt(year, month, number(day.get(..2)?)?)?,
        day.get(2..)?,
    ))
}

fn clock(text: &str) -> Option<(u32, u32, u32, u32)> {
    let (main, fraction) = text
        .split_once(['.', ','])
        .map_or((text, None), |(t, f)| (t, Some(f)));
    let hour = number(main.get(..2)?)?;
    let tail = main.get(2..)?;
    let sep = if tail.starts_with(':') { ":" } else { "" };
    if tail.is_empty() && fraction.is_none() {
        return Some((hour, 0, 0, 0));
    }
    let minute = tail.strip_prefix(sep)?;
    let m = number(minute.get(..2)?)?;
    let tail = minute.get(2..)?;
    if tail.is_empty() && fraction.is_none() {
        return Some((hour, m, 0, 0));
    }
    let second = tail.strip_prefix(sep)?;
    if second.len() != 2 {
        return None;
    }
    let us = match fraction {
        Some(f) if !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()) => {
            let len = f.len().min(6);
            number(&f[..len])? * 10u32.pow(6 - len as u32)
        }
        Some(_) => return None,
        None => 0,
    };
    Some((hour, m, number(second)?, us))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equivalent_week_calendar_and_compact_cursor_dates() {
        let expected = parse("2026-02-09T15:30:00.123456").unwrap();
        for stamp in [
            "2026W071🙂153000,1234569Z",
            "2026-W07T15:30:00.123456+02:30:10",
            "20260209 153000.123456-04",
        ] {
            assert_eq!(parse(stamp), Some(expected), "{stamp}");
        }
    }

    #[test]
    fn midnight_rollover_requires_a_valid_following_date() {
        assert_eq!(parse("20260301X24"), parse("2026-03-02"));
        for invalid in [
            "20260230",
            "99991231T24",
            "20260301T24:01",
            "20260301T12+24",
            "2026-W00",
        ] {
            assert_eq!(parse(invalid), None, "{invalid}");
        }
    }
}
