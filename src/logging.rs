extern crate chrono;
extern crate log;

use chrono::Local;
use log::{LogLevel, LogMetadata, LogRecord};

pub struct SimpleLogger {
    log_level: LogLevel,
    lcore_id: i32,
}

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= self.log_level
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            let s = format!("{}", record.args());
            // Filter out mio events
            if record.level() != LogLevel::Trace
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
}

pub fn init(log_level: LogLevel, core_id: i32) {
    log::set_logger(|max_log_level| {
        max_log_level.set(log_level.to_log_level_filter());
        Box::new(SimpleLogger {
            log_level,
            lcore_id: core_id,
        })
    })
    .unwrap_or_else(|e| {
        error!("failed to init logging: {}", e);
    });
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
