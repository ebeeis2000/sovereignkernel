use rand::RngCore;
use sha2::{Digest, Sha256};
use vault_common::{VaultError, VaultResult};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct ShamirShare {
    pub index: u8,
    pub data: Vec<u8>,
    pub fingerprint: [u8; 32],
}

impl Drop for ShamirShare {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

pub struct ShamirScheme {
    threshold: usize,
    total: usize,
}

impl ShamirScheme {
    pub fn new(threshold: usize, total: usize) -> VaultResult<Self> {
        if threshold < 2 {
            return Err(VaultError::Shamir("Threshold moet minimaal 2 zijn".into()));
        }
        if total < threshold {
            return Err(VaultError::Shamir("Total moet >= threshold zijn".into()));
        }
        if total > 255 {
            return Err(VaultError::Shamir("Maximum 255 shares".into()));
        }
        Ok(Self { threshold, total })
    }

    pub fn split(&self, secret: &[u8]) -> VaultResult<Vec<ShamirShare>> {
        if secret.is_empty() {
            return Err(VaultError::Shamir("Secret mag niet leeg zijn".into()));
        }

        let mut shares: Vec<Vec<u8>> = vec![vec![0u8; secret.len()]; self.total];
        let mut rng = rand::rngs::OsRng;

        for byte_idx in 0..secret.len() {
            let mut coefficients = vec![0u8; self.threshold];
            coefficients[0] = secret[byte_idx];
            for coeff in coefficients.iter_mut().skip(1) {
                let mut b = [0u8; 1];
                rng.fill_bytes(&mut b);
                *coeff = b[0];
            }

            for share_idx in 0..self.total {
                let x = (share_idx as u8) + 1;
                shares[share_idx][byte_idx] = evaluate_polynomial(&coefficients, x);
            }

            coefficients.zeroize();
        }

        let result: Vec<ShamirShare> = shares
            .into_iter()
            .enumerate()
            .map(|(i, data)| {
                let fingerprint = {
                    let mut h = Sha256::new();
                    h.update(&data);
                    h.finalize().into()
                };
                ShamirShare { index: (i as u8) + 1, data, fingerprint }
            })
            .collect();

        Ok(result)
    }

    pub fn combine(&self, shares: &[ShamirShare]) -> VaultResult<Vec<u8>> {
        if shares.len() < self.threshold {
            return Err(VaultError::Shamir(format!(
                "Minimaal {} shares nodig, {} gegeven",
                self.threshold,
                shares.len()
            )));
        }

        let secret_len = shares[0].data.len();
        if shares.iter().any(|s| s.data.len() != secret_len) {
            return Err(VaultError::Shamir("Shares hebben ongelijke lengte".into()));
        }

        let mut secret = vec![0u8; secret_len];
        let xs: Vec<u8> = shares.iter().map(|s| s.index).collect();

        for byte_idx in 0..secret_len {
            let ys: Vec<u8> = shares.iter().map(|s| s.data[byte_idx]).collect();
            secret[byte_idx] = lagrange_interpolate(&xs[..self.threshold], &ys[..self.threshold], 0);
        }

        Ok(secret)
    }

    pub fn threshold(&self) -> usize {
        self.threshold
    }

    pub fn total(&self) -> usize {
        self.total
    }
}

fn evaluate_polynomial(coefficients: &[u8], x: u8) -> u8 {
    let mut result: u8 = 0;
    let mut x_power: u8 = 1;
    for &coeff in coefficients {
        result ^= gf256_mul(coeff, x_power);
        x_power = gf256_mul(x_power, x);
    }
    result
}

fn lagrange_interpolate(xs: &[u8], ys: &[u8], at: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..xs.len() {
        let mut basis: u8 = 1;
        for j in 0..xs.len() {
            if i == j { continue; }
            let num = at ^ xs[j];
            let den = xs[i] ^ xs[j];
            basis = gf256_mul(basis, gf256_mul(num, gf256_inv(den)));
        }
        result ^= gf256_mul(ys[i], basis);
    }
    result
}

fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(b & 1);
        result ^= a & mask;
        let carry = a & 0x80;
        a <<= 1;
        let reduce_mask = 0u8.wrapping_sub(carry >> 7);
        a ^= 0x1b & reduce_mask;
        b >>= 1;
    }
    result
}

fn gf256_inv(a: u8) -> u8 {
    if a == 0 { return 0; }
    let mut result = a;
    for _ in 0..6 {
        result = gf256_mul(result, result);
        result = gf256_mul(result, a);
    }
    gf256_mul(result, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_combine() {
        let secret = b"This is a test secret for Shamir!";
        let scheme = ShamirScheme::new(3, 5).unwrap();
        let shares = scheme.split(secret).unwrap();
        assert_eq!(shares.len(), 5);

        let recovered = scheme.combine(&shares[0..3]).unwrap();
        assert_eq!(recovered, secret);

        let recovered2 = scheme.combine(&shares[2..5]).unwrap();
        assert_eq!(recovered2, secret);
    }

    #[test]
    fn test_insufficient_shares() {
        let secret = b"secret";
        let scheme = ShamirScheme::new(3, 5).unwrap();
        let shares = scheme.split(secret).unwrap();
        assert!(scheme.combine(&shares[0..2]).is_err());
    }
}
