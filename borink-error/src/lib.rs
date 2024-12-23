use core::fmt;
use std::error::Error;

/// An error context consisting of a boxed type, to ensure the error size is as small as possible.
/// A boxed string is smaller than a string, for example. Adds an additional layer of indirection,
/// but this cost is only paid when an actual error occurs, which is assumed to not be in the hot
/// path of an application.
#[derive(Debug)]
#[repr(transparent)]
pub struct ErrorContext<T>(pub Box<T>);

impl<T> ErrorContext<T> {
    pub fn new(inner: T) -> Self {
        Self(Box::new(inner))
    }
}

/// A boxed string as context to reduce the struct size. Implements From<String> and From<&str>
/// so use `"<your message>".into()` or `your_string.into()` to create.
pub type StringContext = ErrorContext<String>;

impl From<String> for StringContext {
    fn from(value: String) -> Self {
        ErrorContext::new(value)
    }
}

impl From<&str> for StringContext {
    fn from(value: &str) -> Self {
        ErrorContext::new(value.to_owned())
    }
}

impl fmt::Display for StringContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct ContextSource<E: Error>(pub Box<(String, E)>);

impl<E: Error> ContextSource<E> {
    pub fn new<S: Into<String>>(message: S, source: E) -> Self {
        Self(Box::new((message.into(), source)))
    }
}

impl<T: Error> fmt::Display for ContextSource<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (message, source) = self.0.as_ref();
        write!(f, "{} caused by {}", message, source)
    }
}

impl<T: Error + 'static> Error for ContextSource<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0.as_ref().1)
    }
}

pub trait ErrorWithContext {
    fn with_context<S: Into<String>>(self, context: S) -> ContextSource<Self>
    where
        Self: std::error::Error + Sized,
    {
        ContextSource::new(context, self)
    }
}

impl<T> ErrorWithContext for T where T: Error + Sized {}

pub trait WrapErrorWithContext<T, E: Error> {
    fn map_err_with_context<S: Into<String>>(self, message: S) -> Result<T, ContextSource<E>>;
}

impl<T, E: Error> WrapErrorWithContext<T, E> for Result<T, E> {
    fn map_err_with_context<S: Into<String>>(self, message: S) -> Result<T, ContextSource<E>> {
        self.map_err(|e| ContextSource::new(message, e))
    }
}
