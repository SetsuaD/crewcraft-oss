// T005: enrollment code display form, check symbol and parsing.
#![allow(clippy::unwrap_used)] // helper functions outside #[test] unwrap too
use crewcraft_enroll::{EnrollmentCode, Error};

fn counting() -> EnrollmentCode {
    let mut b = [0u8; 20];
    for (i, x) in b.iter_mut().enumerate() {
        *x = i as u8 + 1;
    }
    EnrollmentCode::from_bytes(b)
}

#[test]
fn display_form() {
    assert_eq!(EnrollmentCode::from_bytes([0; 20]).to_display(), "CC1-0000-0000-0000-0000-0000-0000-0000-0000-0");
    assert_eq!(EnrollmentCode::from_bytes([255; 20]).to_display(), "CC1-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-8");
    assert_eq!(counting().to_display(), "CC1-0410-6105-0R3G-G28A-1C60-T3GF-208H-44RM-P");
}

#[test]
fn check_symbol_is_mod_37() {
    assert_eq!(EnrollmentCode::from_bytes([0; 20]).check_symbol(), '0');
    assert_eq!(EnrollmentCode::from_bytes([255; 20]).check_symbol(), '8');
    assert_eq!(counting().check_symbol(), 'P');
}

#[test]
fn parse_round_trips() {
    for c in [EnrollmentCode::from_bytes([0; 20]), EnrollmentCode::from_bytes([255; 20]), counting()] {
        assert_eq!(EnrollmentCode::parse(&c.to_display()).unwrap(), c);
    }
}

#[test]
fn parse_forgives_case_spacing_and_lookalikes() {
    let want = counting();
    assert_eq!(EnrollmentCode::parse("cc1 0410 6105 0r3g g28a 1c60 t3gf 208h 44rm p").unwrap(), want);
    assert_eq!(EnrollmentCode::parse("CC1-O41O-61O5-OR3G-G28A-IC6O-T3GF-2O8H-44RM-P").unwrap(), want); // O->0, I->1
    assert_eq!(EnrollmentCode::parse("CC1-0410-6105-0R3G-G28A-lC60-T3GF-208H-44RM-P").unwrap(), want); // l->1
}

#[test]
fn parse_rejects_bad_input() {
    assert_eq!(EnrollmentCode::parse("CC2-0410-6105-0R3G-G28A-1C60-T3GF-208H-44RM-P"), Err(Error::BadPrefix));
    assert_eq!(EnrollmentCode::parse("0410-6105-0R3G-G28A-1C60-T3GF-208H-44RM-P"), Err(Error::BadPrefix));
    assert_eq!(EnrollmentCode::parse("CC1-0410-6105-0R3G-G28A-1C60-T3GF-208H-44R-P"), Err(Error::BadLength));
    assert_eq!(EnrollmentCode::parse("CC1-0410-6105-0R3G-G28A-1C60-T3GF-208H-44RU-P"), Err(Error::BadCharacter)); // U is not data
    assert_eq!(EnrollmentCode::parse("CC1-0410-6105-0R3G-G28A-1C60-T3GF-208H-44RM-Q"), Err(Error::BadChecksum));
    assert_eq!(EnrollmentCode::parse("CC1-0410-6105-0R3G-G28A-1C60-T3GF-208H-44RN-P"), Err(Error::BadChecksum)); // one typo
}

#[test]
fn debug_never_prints_the_secret() {
    assert_eq!(format!("{:?}", counting()), "EnrollmentCode(..)");
}
