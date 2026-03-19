//! JNI Error types - minimal implementation for production bridge

#[derive(Debug, Clone)]
pub enum JniErrorCode {
    InvalidInput = 1,
    ProcessingFailed = 2,
    EncodingFailed = 3,
    RuntimeError = 4,
}

impl JniErrorCode {
    pub fn as_i32(&self) -> i32 {
        self.clone() as i32
    }
}
