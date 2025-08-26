/// Risk scoring utilities based on counts of findings.
///
/// The scoring model uses a weighted average of finding severities
/// (Critical=9, High=7, Medium=4, Low=1) to produce a single metric
/// between 0 and 9.
#[derive(Debug, Default, Clone, Copy)]
pub struct Host {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Network {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

impl Host {
    /// Compute the risk score for this host.
    pub fn risk_score(&self) -> f32 {
        compute_score(self.critical, self.high, self.medium, self.low)
    }
}

impl Network {
    /// Compute the overall network risk score.
    pub fn risk_score(&self) -> f32 {
        compute_score(self.critical, self.high, self.medium, self.low)
    }
}

fn compute_score(critical: u32, high: u32, medium: u32, low: u32) -> f32 {
    const CRITICAL_W: f32 = 9.0;
    const HIGH_W: f32 = 7.0;
    const MEDIUM_W: f32 = 4.0;
    const LOW_W: f32 = 1.0;
    let total = critical + high + medium + low;
    if total == 0 {
        return 0.0;
    }
    let weighted = critical as f32 * CRITICAL_W
        + high as f32 * HIGH_W
        + medium as f32 * MEDIUM_W
        + low as f32 * LOW_W;
    weighted / total as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_average() {
        let host = Host {
            critical: 1,
            high: 1,
            medium: 1,
            low: 1,
        };
        // (9 + 7 + 4 + 1) / 4 = 5.25
        assert!((host.risk_score() - 5.25).abs() < f32::EPSILON);
    }

    #[test]
    fn zero_when_no_findings() {
        let network = Network::default();
        assert_eq!(network.risk_score(), 0.0);
    }
}
