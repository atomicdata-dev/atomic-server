/*!
Plugins extend functionality of Atomic Server.
They are written in Rust and compiled to WebAssembly.
Currently, they are loaded at compile time, but in the future they will be loaded at runtime.
*/

pub mod bindings_generator;
pub mod generated_runtime;
pub mod host;
