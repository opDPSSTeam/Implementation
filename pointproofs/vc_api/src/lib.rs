mod commit;
mod util;

extern crate libc;
use std::ffi::{CStr, CString};

#[no_mangle]
pub extern "C" fn fr_plus(s1: *const libc::c_char, s2: *const libc::c_char) -> *const libc::c_char {
    let s1_str = unsafe { CStr::from_ptr(s1).to_str().unwrap() };
    let s2_str = unsafe { CStr::from_ptr(s2).to_str().unwrap() };
    let f1 = util::str_to_message(s1_str);
    let f2 = util::str_to_message(s2_str);
    let res = util::message_to_str(f1 + f2);
    CString::new(res).unwrap().into_raw()
}

const GENERATE_PARAMS: [fn() -> String; 42] = [
  commit::gen_params::<4>,
  commit::gen_params::<7>,
  commit::gen_params::<10>,
  commit::gen_params::<13>,
  commit::gen_params::<16>,
  commit::gen_params::<19>,
  commit::gen_params::<22>,
  commit::gen_params::<25>,
  commit::gen_params::<28>,
  commit::gen_params::<31>,
  commit::gen_params::<34>,
  commit::gen_params::<37>,
  commit::gen_params::<40>,
  commit::gen_params::<43>,
  commit::gen_params::<46>,
  commit::gen_params::<49>,
  commit::gen_params::<52>,
  commit::gen_params::<55>,
  commit::gen_params::<58>,
  commit::gen_params::<61>,
  commit::gen_params::<64>,
  commit::gen_params::<67>,
  commit::gen_params::<70>,
  commit::gen_params::<73>,
  commit::gen_params::<76>,
  commit::gen_params::<79>,
  commit::gen_params::<82>,
  commit::gen_params::<85>,
  commit::gen_params::<88>,
  commit::gen_params::<91>,
  commit::gen_params::<94>,
  commit::gen_params::<97>,
  commit::gen_params::<100>,
  commit::gen_params::<103>,
  commit::gen_params::<106>,
  commit::gen_params::<109>,
  commit::gen_params::<112>,
  commit::gen_params::<115>,
  commit::gen_params::<118>,
  commit::gen_params::<121>,
  commit::gen_params::<124>,
  commit::gen_params::<127>
];
const COMMIT: [fn(&str, &str) -> String; 42] = [
  commit::commit::<4>,
  commit::commit::<7>,
  commit::commit::<10>,
  commit::commit::<13>,
  commit::commit::<16>,
  commit::commit::<19>,
  commit::commit::<22>,
  commit::commit::<25>,
  commit::commit::<28>,
  commit::commit::<31>,
  commit::commit::<34>,
  commit::commit::<37>,
  commit::commit::<40>,
  commit::commit::<43>,
  commit::commit::<46>,
  commit::commit::<49>,
  commit::commit::<52>,
  commit::commit::<55>,
  commit::commit::<58>,
  commit::commit::<61>,
  commit::commit::<64>,
  commit::commit::<67>,
  commit::commit::<70>,
  commit::commit::<73>,
  commit::commit::<76>,
  commit::commit::<79>,
  commit::commit::<82>,
  commit::commit::<85>,
  commit::commit::<88>,
  commit::commit::<91>,
  commit::commit::<94>,
  commit::commit::<97>,
  commit::commit::<100>,
  commit::commit::<103>,
  commit::commit::<106>,
  commit::commit::<109>,
  commit::commit::<112>,
  commit::commit::<115>,
  commit::commit::<118>,
  commit::commit::<121>,
  commit::commit::<124>,
  commit::commit::<127>
];
const OPEN: [fn(&str, &str, usize) -> String; 42] = [
  commit::open::<4>,
  commit::open::<7>,
  commit::open::<10>,
  commit::open::<13>,
  commit::open::<16>,
  commit::open::<19>,
  commit::open::<22>,
  commit::open::<25>,
  commit::open::<28>,
  commit::open::<31>,
  commit::open::<34>,
  commit::open::<37>,
  commit::open::<40>,
  commit::open::<43>,
  commit::open::<46>,
  commit::open::<49>,
  commit::open::<52>,
  commit::open::<55>,
  commit::open::<58>,
  commit::open::<61>,
  commit::open::<64>,
  commit::open::<67>,
  commit::open::<70>,
  commit::open::<73>,
  commit::open::<76>,
  commit::open::<79>,
  commit::open::<82>,
  commit::open::<85>,
  commit::open::<88>,
  commit::open::<91>,
  commit::open::<94>,
  commit::open::<97>,
  commit::open::<100>,
  commit::open::<103>,
  commit::open::<106>,
  commit::open::<109>,
  commit::open::<112>,
  commit::open::<115>,
  commit::open::<118>,
  commit::open::<121>,
  commit::open::<124>,
  commit::open::<127>
];
const VERIFY: [fn(&str, &str, &str, usize, &str) -> bool; 42] = [
  commit::verify::<4>,
  commit::verify::<7>,
  commit::verify::<10>,
  commit::verify::<13>,
  commit::verify::<16>,
  commit::verify::<19>,
  commit::verify::<22>,
  commit::verify::<25>,
  commit::verify::<28>,
  commit::verify::<31>,
  commit::verify::<34>,
  commit::verify::<37>,
  commit::verify::<40>,
  commit::verify::<43>,
  commit::verify::<46>,
  commit::verify::<49>,
  commit::verify::<52>,
  commit::verify::<55>,
  commit::verify::<58>,
  commit::verify::<61>,
  commit::verify::<64>,
  commit::verify::<67>,
  commit::verify::<70>,
  commit::verify::<73>,
  commit::verify::<76>,
  commit::verify::<79>,
  commit::verify::<82>,
  commit::verify::<85>,
  commit::verify::<88>,
  commit::verify::<91>,
  commit::verify::<94>,
  commit::verify::<97>,
  commit::verify::<100>,
  commit::verify::<103>,
  commit::verify::<106>,
  commit::verify::<109>,
  commit::verify::<112>,
  commit::verify::<115>,
  commit::verify::<118>,
  commit::verify::<121>,
  commit::verify::<124>,
  commit::verify::<127>
];

#[no_mangle]
pub extern "C" fn generate_params(number: libc::c_int) -> *const libc::c_char {
    let res = GENERATE_PARAMS[number as usize]();
    CString::new(res).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn commit(
    number: libc::c_int,
    srs: *const libc::c_char,
    messages: *const libc::c_char,
) -> *const libc::c_char {
    let srs = unsafe { CStr::from_ptr(srs).to_str().unwrap() };
    let messages = unsafe { CStr::from_ptr(messages).to_str().unwrap() };
    let res = COMMIT[number as usize](srs, messages);
    CString::new(res).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn open_(
    number: libc::c_int,
    srs: *const libc::c_char,
    messages: *const libc::c_char,
    pos: libc::c_int,
) -> *const libc::c_char {
    let srs = unsafe { CStr::from_ptr(srs).to_str().unwrap() };
    let messages = unsafe { CStr::from_ptr(messages).to_str().unwrap() };
    let res = OPEN[number as usize](srs, messages, pos as usize);
    CString::new(res).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn verify(
    number: libc::c_int,
    srs: *const libc::c_char,
    commitment: *const libc::c_char,
    message: *const libc::c_char,
    pos: libc::c_int,
    witness: *const libc::c_char,
) -> libc::c_int {
    let srs = unsafe { CStr::from_ptr(srs).to_str().unwrap() };
    let commitment = unsafe { CStr::from_ptr(commitment).to_str().unwrap() };
    let message = unsafe { CStr::from_ptr(message).to_str().unwrap() };
    let witness = unsafe { CStr::from_ptr(witness).to_str().unwrap() };

    let res = VERIFY[number as usize](srs, commitment, message, pos as usize, witness);
    res as libc::c_int
}
