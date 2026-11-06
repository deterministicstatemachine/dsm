// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the identify image read from a board's chip, and its answer on the wire.
//!
//! The identify image reads the TROPIC01 and writes nothing, to the chip or to the board's OTP. A board
//! runs it to say which chip it carries, and what that chip already holds, before anything is decided
//! for it: the part and its firmware, its certificates, its configuration, its pairing slots, its
//! counter, the resident key's slot and how much of R-memory is written.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::proto::{decode_request, encode_response, pb};
use crate::service::{err, fail, ok, refusal};

/// One thing read from the chip: its value, or why it did not read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChipReading {
    pub name: String,
    pub value: Result<String, String>,
}

impl ChipReading {
    pub fn new(name: &str, value: Result<String, String>) -> Self {
        Self {
            name: String::from(name),
            value,
        }
    }
}

/// Everything the identify image read.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChipSurvey {
    pub readings: Vec<ChipReading>,
    /// The chip's X.509 certificates as it gives them: device, part group, TROPIC01 CA, root.
    pub certificates: Vec<Vec<u8>>,
}

/// The identify image's answer to `frame`: what it read, to `OP_IDENTIFY`; to anything else, that this
/// image does nothing else.
pub fn answer(frame: &[u8], survey: &ChipSurvey) -> Vec<u8> {
    let op = match decode_request(frame) {
        Ok(req) => req.op,
        Err(_undecodable) => return encode_response(&fail(0, err::BAD_PROTO)),
    };
    if op != pb::Op::Identify as i32 {
        return refusal(
            op,
            err::IDENTIFY_IMAGE,
            "this image reads the chip and says what it is; it serves nothing else",
        );
    }
    let readings = survey
        .readings
        .iter()
        .map(|reading| match &reading.value {
            Ok(value) => pb::ChipReading {
                name: reading.name.clone(),
                value: value.clone(),
                unread: String::new(),
            },
            Err(why) => pb::ChipReading {
                name: reading.name.clone(),
                value: String::new(),
                unread: why.clone(),
            },
        })
        .collect();
    encode_response(&pb::ApplianceResponse {
        chip_readings: readings,
        chip_certificates: survey.certificates.clone(),
        ..ok(op)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{decode_response, encode_request};

    fn survey() -> ChipSurvey {
        ChipSurvey {
            readings: alloc::vec![
                ChipReading::new("part number", Ok(String::from("TR01-C2P-T202"))),
                ChipReading::new("counter", Err(String::from("CounterInvalid"))),
            ],
            certificates: alloc::vec![alloc::vec![0x30, 0x82], alloc::vec![0x30, 0x81]],
        }
    }

    fn request(op: pb::Op) -> Vec<u8> {
        encode_request(&pb::ApplianceRequest {
            op: op as i32,
            ..Default::default()
        })
    }

    /// The answer carries every reading, each its value or why it did not read, and the certificates.
    #[test]
    fn an_identify_request_is_answered_with_what_was_read() {
        let survey = survey();
        let answer = match decode_response(&answer(&request(pb::Op::Identify), &survey)) {
            Ok(answer) => answer,
            Err(e) => panic!("the answer does not decode: {e:?}"),
        };
        assert!(answer.ok);
        assert_eq!(answer.chip_certificates, survey.certificates);
        let named: Vec<(&str, &str, &str)> = answer
            .chip_readings
            .iter()
            .map(|r| (r.name.as_str(), r.value.as_str(), r.unread.as_str()))
            .collect();
        assert_eq!(
            named,
            [
                ("part number", "TR01-C2P-T202", ""),
                ("counter", "", "CounterInvalid")
            ]
        );
    }

    /// The image serves nothing else: an install, a try-run or a spend is refused as such.
    #[test]
    fn anything_but_an_identify_request_is_refused() {
        for op in [
            pb::Op::Provision,
            pb::Op::TryRun,
            pb::Op::Prepare,
            pb::Op::Status,
        ] {
            let answer = match decode_response(&answer(&request(op), &survey())) {
                Ok(answer) => answer,
                Err(e) => panic!("the answer does not decode: {e:?}"),
            };
            assert!(!answer.ok, "{op:?} was served");
            assert_eq!(answer.error, err::IDENTIFY_IMAGE, "{op:?}");
            assert!(
                answer.chip_readings.is_empty(),
                "{op:?} carried the readings"
            );
        }
    }
}
