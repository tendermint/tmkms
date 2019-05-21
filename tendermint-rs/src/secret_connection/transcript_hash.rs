use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const HKDF_INFO: &[u8] = b"TENDERMINT_SECRET_CONNECTION_TRANSCRIPT_HASH";
const TRANSCRIPT_HASH_INIT: &[u8] = b"INIT_HANDSHAKE";

/// Key Derivation Function for `SecretConnection` (HKDF)
pub struct TranscriptHash {
    /// transcript state
    hash_state: [u8; 32],
}

impl TranscriptHash{

    /// Initialization function
    pub fn init()->Self{
        let mut buf = [0u8;32]; 
        
        Hkdf::<Sha256>::extract(None, TRANSCRIPT_HASH_INIT)
            .expand(HKDF_INFO, &mut buf)
            .unwrap();
        return TranscriptHash{hash_state:buf};
    }
    /// Update function
    pub fn update(&mut self,data: &[u8])->&mut Self{
        Hkdf::<Sha256>::extract(Some(&self.hash_state), data)
            .expand(HKDF_INFO, &mut self.hash_state)
            .unwrap();
        return self;
    }

    /// Extract the internal state
    pub fn extract(&mut self) -> [u8;32]{
        return self.hash_state.clone();
    }
}


impl Drop for TranscriptHash {
    fn drop(&mut self) {
        self.hash_state.zeroize();
    }
}
