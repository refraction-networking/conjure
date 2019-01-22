use flow_tracker::Flow;


const SEED_LEN: usize = 16;

pub struct SessionState
{
    pub flow: Flow,
    pub seed: [u8; SEED_LEN],
}


impl SessionState
{
    pub fn new(f: &Flow, s: &[u8]) -> SessionState
    {
        let mut a: [u8; SEED_LEN] = Default::default();
        a.copy_from_slice(&s[0..SEED_LEN]);
        SessionState {
            flow: *f,
            seed: a,
        }
    }
}
