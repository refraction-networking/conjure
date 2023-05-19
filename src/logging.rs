extern crate chrono;
extern crate log;

use chrono::Local;
use log::{Level, Metadata, Record};

pub struct SimpleLogger {
    log_level: Level,
    lcore_id: i32,
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.log_level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let s = format!("{}", record.args());
            // Filter out mio events
            if record.level() != Level::Trace
                || (!s.starts_with("event loop")
                    && !s.starts_with("tick_to")
                    && !s.starts_with("ticking"))
            {
                let t = Local::now();
                // let t = time::OffsetDateTime::now_local().unwrap();
                // unwrap relies on "%b %d, %Y %T" being a valid format string.
                let t_s = t.format("%Y-%m-%d %H:%M:%S.%f %z").to_string();
                println!("{} (Core {}) {}: {}", t_s, self.lcore_id, record.level(), s);
            }
        }
    }

    fn flush(&self) {}
}

static mut LOGGER: SimpleLogger = SimpleLogger {
    log_level: Level::Error,
    lcore_id: 0,
};

pub fn init(log_level: Level, core_id: i32) {
    unsafe {
        LOGGER.lcore_id = core_id;
        LOGGER.log_level = log_level;
        log::set_logger(&LOGGER).unwrap_or_else(|e| {
            error!("failed to init logging: {}", e);
        });
    }
    log::set_max_level(log_level.to_level_filter());
}

//HACKY_CFG_NO_TEST_BEGIN
#[macro_export]
macro_rules! report {
    ($($arg:tt)*) => {{
        let s = format!("{}", format_args!($($arg)*));
        debug!("{}", s);
        let s2 = format!("{}\n", s);
        $crate::c_api::c_write_reporter(s2);
    }};
}
//HACKY_CFG_NO_TEST_END*/
/*//HACKY_CFG_YES_TEST_BEGIN
#[macro_export]
macro_rules! report {
    ($($arg:tt)*) => {{
        let s = format!("{}\n", format_args!($($arg)*));
        debug!("{}", s);
    }};
}
//HACKY_CFG_YES_TEST_END*/
