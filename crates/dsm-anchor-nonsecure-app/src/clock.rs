// SPDX-License-Identifier: MIT OR Apache-2.0
//! The Non-secure side's clock: `embassy-time`'s driver on TIMER1 (TIMER0 is the monitor's). A
//! microsecond count since boot and one alarm, ALARM0, whose interrupt wakes the task whose time
//! has come. The monitor grants TIMER1 and targets `TIMER1_IRQ_0` at the Non-secure state.
//!
//! Nothing here is time in the protocol's sense: it paces the radio driver's waits and the
//! watchdog keepalive. No DSM validity or ordering reads it.

use core::cell::RefCell;
use core::task::Waker;

use critical_section::{CriticalSection, Mutex};
use embassy_time_driver::Driver;
use embassy_time_queue_utils::Queue;
use hal::pac::interrupt;
use rp235x_hal as hal;

struct Timer1Driver {
    queue: Mutex<RefCell<Queue>>,
}

embassy_time_driver::time_driver_impl!(static DRIVER: Timer1Driver = Timer1Driver {
    queue: Mutex::new(RefCell::new(Queue::new())),
});

fn timer() -> &'static hal::pac::timer1::RegisterBlock {
    unsafe { &*hal::pac::TIMER1::ptr() }
}

/// Bring TIMER1 up: release its reset, run it from the 1 MHz tick, and enable ALARM0's interrupt.
/// Before the first gateway crossing, while the Non-secure side still holds RESETS.
pub fn init(resets: &mut hal::pac::RESETS) {
    resets.reset().modify(|_, w| w.timer1().set_bit());
    resets.reset().modify(|_, w| w.timer1().clear_bit());
    while resets.reset_done().read().timer1().bit_is_clear() {}
    let t = timer();
    t.inte().write(|w| w.alarm_0().set_bit());
    unsafe {
        cortex_m::peripheral::NVIC::unmask(hal::pac::Interrupt::TIMER1_IRQ_0);
    }
}

impl Timer1Driver {
    /// Arm ALARM0 for `at` microseconds since boot. The alarm compares the low 32 bits only, so a
    /// time more than half that span away is armed for the span's middle and re-armed on firing.
    /// Answers whether the alarm is set for a moment still ahead.
    fn set_alarm(&self, _cs: CriticalSection, at: u64) -> bool {
        let t = timer();
        let now = self.now();
        let horizon = now + (1u64 << 31);
        let target = at.min(horizon);
        t.alarm0().write(|w| unsafe { w.bits(target as u32) });
        // Armed for a moment already passed: the interrupt will not come, so report it as missed
        // and let the caller run the queue now.
        self.now() < target
    }
}

impl Driver for Timer1Driver {
    fn now(&self) -> u64 {
        let t = timer();
        loop {
            let hi = t.timerawh().read().bits();
            let lo = t.timerawl().read().bits();
            let hi_again = t.timerawh().read().bits();
            if hi == hi_again {
                return (u64::from(hi) << 32) | u64::from(lo);
            }
        }
    }

    fn schedule_wake(&self, at: u64, waker: &Waker) {
        critical_section::with(|cs| {
            let mut queue = self.queue.borrow(cs).borrow_mut();
            if queue.schedule_wake(at, waker) {
                let mut next = queue.next_expiration(self.now());
                while !self.set_alarm(cs, next) {
                    next = queue.next_expiration(self.now());
                }
            }
        })
    }
}

#[interrupt]
fn TIMER1_IRQ_0() {
    let t = timer();
    t.intr().write(|w| w.alarm_0().clear_bit_by_one());
    critical_section::with(|cs| {
        let mut queue = DRIVER.queue.borrow(cs).borrow_mut();
        let mut next = queue.next_expiration(DRIVER.now());
        while !DRIVER.set_alarm(cs, next) {
            next = queue.next_expiration(DRIVER.now());
        }
    });
}
