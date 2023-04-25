use std::collections::HashMap;
use std::error::Error;
use std::fmt::{self, Display};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub trait Limit: Send + Sync {
    fn reset(&mut self);

    fn count_or_drop(&mut self, key: Hashable) -> Result<(), Box<dyn Error>>;

    fn count_or_drop_many(&mut self, keys: Vec<Hashable>) -> Result<Hashable, Box<dyn Error>>;
}

pub struct Limiter {
    counts: Option<HashMap<Hashable, AtomicU64>>,
    count: AtomicU64,
    total: u64,
    limit: u64,
    flag: Arc<AtomicBool>,
}

impl Limiter {
    pub fn limit<T: Into<Hashable> + Clone>(
        keys: Vec<T>,
        limit: u64,
        flag: Arc<AtomicBool>,
    ) -> Box<dyn Limit> {
        match keys.is_empty() {
            false => {
                let n = keys.len() as u64;
                Box::new(Limiter {
                    counts: Some(
                        Hashable::from(keys)
                            .into_iter()
                            .map(|asn| (asn, AtomicU64::new(0)))
                            .collect(),
                    ),
                    limit,
                    count: AtomicU64::new(0),
                    total: limit * n,
                    flag,
                })
            }
            true => Box::new(Limiter {
                counts: None,
                limit,
                count: AtomicU64::new(0),
                total: limit,
                flag,
            }),
        }
    }
}

impl Limit for Limiter {
    fn reset(&mut self) {
        if let Some(count_obj) = &mut self.counts {
            count_obj
                .iter_mut()
                .for_each(|(_, c)| c.store(0, Ordering::Relaxed));
        }
        self.count.store(0, Ordering::Relaxed);
    }

    fn count_or_drop(&mut self, key: Hashable) -> Result<(), Box<dyn Error>> {
        // Is the flag already set?
        if self.flag.load(Ordering::Relaxed) {
            return Err(LimitError::Flag)?;
        }

        // Have we reached the total count for this limiter?
        if self.count.load(Ordering::Relaxed) >= self.total {
            self.flag.store(true, Ordering::Relaxed);
            return Err(LimitError::Full(Hashable::Z))?;
        }

        // Is this an ASN / CC we care about, and if so have we reached the
        // limit for the individual asn counter?
        if let Some(count_obj) = &mut self.counts {
            match count_obj.get_mut(&key) {
                Some(c) => {
                    if c.load(Ordering::Relaxed) >= self.limit {
                        return Err(LimitError::Full(key))?;
                    }
                    c.fetch_add(1, Ordering::Relaxed);
                }
                None => return Err(LimitError::UnknownKey)?,
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    fn count_or_drop_many<'a>(&mut self, keys: Vec<Hashable>) -> Result<Hashable, Box<dyn Error>> {
        if self.flag.load(Ordering::Relaxed) {
            return Err(LimitError::Flag)?;
        }

        if self.count.load(Ordering::Relaxed) >= self.total {
            self.flag.store(true, Ordering::Relaxed);
            return Err(LimitError::Full(Hashable::Z))?;
        }

        if keys.is_empty() {
            return Ok(Hashable::Z);
        }

        match &mut self.counts {
            None => return Ok(keys[0].clone()),
            Some(count_obj) => {
                for key in keys.into_iter() {
                    // Is this an ASN / CC we care about, and if so have we reached the
                    // limit for the individual asn counter?
                    match count_obj.get_mut(&key) {
                        Some(c) => {
                            if c.load(Ordering::Relaxed) >= self.limit {
                                return Err(LimitError::Full(key))?;
                            }
                            c.fetch_add(1, Ordering::Relaxed);
                            self.count.fetch_add(1, Ordering::Relaxed);
                            return Ok(key);
                        }
                        None => continue,
                    }
                }
            }
        }
        Err(LimitError::UnknownKey)?
    }
}

pub fn build(
    l: Option<u64>,
    lpa: Option<u64>,
    lpc: Option<u64>,
    asn_list: Vec<u32>,
    cc_list: Vec<String>,
    flag: Arc<AtomicBool>,
) -> Option<Box<dyn Limit>> {
    if l.is_some_and(|x| x > 0) {
        let len =l.unwrap();
        // println!("building base limiter len: {len}");
        Some(Limiter::limit::<()>(vec![], len, flag))
    } else if let Some(l) = lpa {
        // println!("building asn limiter len: {l}");
        Some(Limiter::limit(asn_list, l, flag))
    } else if let Some(l) = lpc {
        // println!("building cc limiter len: {l}");
        Some(Limiter::limit(cc_list, l, flag))
    } else {
        // println!("no limiter");
        None
    }
}

#[derive(Debug, PartialEq, Hash, Eq, Clone)]
pub enum Hashable {
    Str(String),
    U32(u32),
    Z, // when we don't need a type
}
impl Display for Hashable {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Hashable::Str(s) => write!(f, "{}", s),
            Hashable::U32(s) => write!(f, "{}", s),
            Hashable::Z => write!(f, "count"),
        }
    }
}

impl Hashable {
    fn from<T>(keys: Vec<T>) -> Vec<Self>
    where
        T: Into<Self> + Clone,
    {
        keys.into_iter().map(|k| k.into()).collect()
    }
}

impl From<&String> for Hashable {
    fn from(item: &String) -> Self {
        Hashable::Str(item.clone())
    }
}

impl From<String> for Hashable {
    fn from(item: String) -> Self {
        Hashable::Str(item)
    }
}

impl From<&str> for Hashable {
    fn from(item: &str) -> Self {
        Hashable::Str(String::from(item))
    }
}

impl From<i32> for Hashable {
    fn from(item: i32) -> Self {
        Hashable::U32(item as u32)
    }
}

impl From<&&str> for Hashable {
    fn from(item: &&str) -> Self {
        Hashable::Str(String::from(*item))
    }
}

impl From<&u32> for Hashable {
    fn from(item: &u32) -> Self {
        Hashable::U32(*item)
    }
}

impl From<u32> for Hashable {
    fn from(item: u32) -> Self {
        Hashable::U32(item)
    }
}

impl From<()> for Hashable {
    fn from(_: ()) -> Self {
        Hashable::Z
    }
}

#[derive(Debug)]
pub enum LimitError {
    Full(Hashable),
    UnknownKey,
    Flag,
    OtherError(Box<dyn Error>),
}

impl std::error::Error for LimitError {}

impl fmt::Display for LimitError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LimitError::Full(h) => write!(f, "{h} full"),
            LimitError::UnknownKey => write!(f, "non-tracked key"),
            LimitError::Flag => write!(f, "flag triggered"),
            LimitError::OtherError(e) => write!(f, "{e}"),
        }
    }
}

impl From<Box<dyn Error>> for LimitError {
    fn from(value: Box<dyn Error>) -> Self {
        LimitError::OtherError(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_limit_cc() -> Result<(), Box<dyn Error>> {
        let flag = Arc::new(AtomicBool::new(false));
        let keys = Hashable::from(vec!["ru", "cn", "tm"]);
        let asl = &mut Limiter::limit(keys, 3, Arc::clone(&flag));
        let mut i = 0;

        while asl.count_or_drop("cn".into()).is_ok() {
            i += 1;
        }

        assert_eq!(i, 3);
        let err = asl.count_or_drop("ir".into()).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<LimitError>(),
            Some(LimitError::UnknownKey)
        ));
        let _expected = Hashable::Str(String::from("cn"));
        let err = asl.count_or_drop("cn".into()).unwrap_err();
        assert!(matches!(
            err.downcast_ref::<LimitError>(),
            Some(LimitError::Full(_expected))
        ));
        assert_eq!(i, 3);

        flag.store(false, Ordering::Relaxed);
        asl.reset();

        loop {
            if let Err(e) = asl.count_or_drop("ru".into()) {
                let _expected = Hashable::Str(String::from("ru"));
                assert!(matches!(
                    e.downcast_ref::<LimitError>(),
                    Some(LimitError::Full(_expected))
                ));

                break;
            }
            i += 1;
        }
        assert_eq!(i, 6);
        assert!(asl.count_or_drop("tm".into()).is_ok());
        Ok(())
    }

    #[test]
    fn test_limit_asn() -> Result<(), Box<dyn Error>> {
        let flag = Arc::new(AtomicBool::new(false));
        let keys = Hashable::from(vec![10, 11, 12]);
        let asl = &mut Limiter::limit(keys, 3, Arc::clone(&flag));
        let mut i = 0;

        while asl.count_or_drop(10.into()).is_ok() {
            i += 1;
        }

        assert_eq!(i, 3);
        assert!(matches!(
            asl.count_or_drop("cn".into())
                .unwrap_err()
                .downcast_ref::<LimitError>(),
            Some(LimitError::UnknownKey)
        ));
        assert!(matches!(
            asl.count_or_drop(10.into())
                .unwrap_err()
                .downcast_ref::<LimitError>(),
            Some(LimitError::Full(Hashable::U32(10)))
        ));
        assert_eq!(i, 3);

        flag.store(false, Ordering::Relaxed);
        asl.reset();

        loop {
            if let Err(e) = asl.count_or_drop(11.into()) {
                assert!(matches!(
                    e.downcast_ref::<LimitError>(),
                    Some(LimitError::Full(Hashable::U32(11)))
                ));
                break;
            }
            i += 1;
        }
        assert_eq!(i, 6);
        assert!(asl.count_or_drop(12.into()).is_ok());

        Ok(())
    }

    #[test]
    fn test_limit_total() -> Result<(), Box<dyn Error>> {
        let flag = Arc::new(AtomicBool::new(false));
        let tol = &mut Limiter::limit::<()>(vec![], 10, Arc::clone(&flag));
        let mut i = 0;

        while tol.count_or_drop(Hashable::Z).is_ok() {
            i += 1;
        }

        assert_eq!(i, 10);

        flag.store(false, Ordering::Relaxed);
        tol.reset();

        loop {
            if let Err(e) = tol.count_or_drop("cn".into()) {
                assert!(matches!(
                    e.downcast_ref::<LimitError>(),
                    Some(LimitError::Full(Hashable::Z))
                ));
                break;
            }
            i += 1;
        }
        assert_eq!(i, 20);
        Ok(())
    }
}
