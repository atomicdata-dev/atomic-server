//! QuickJS runtime for creating plugins

#[cfg(test)]
mod test {
    fn wasm() {
        use std::path::PathBuf;

        // create a Loader context
        let loader = Loader::create(None).expect("fail to create a Loader context");

        // load a wasm module from a specified wasm file, and return a WasmEdge AST Module instance
        let path = PathBuf::from("fibonacci.wasm");
        let mut module = loader
            .from_file(path)
            .expect("fail to load the WebAssembly file");

        use wasmedge_sys::{Config, Store, Vm};

        // create a Config context
        let config = Config::create().expect("fail to create a Config context");

        // create a Store context
        let store = Store::create().expect("fail to create a Store context");

        // create a Vm context with the given Config and Store
        let vm = Vm::create(Some(&config), Some(&store)).expect("fail to create a Vm context");

        use wasmedge_sys::Value;

        // run a function
        let returns = vm
            .run_wasm_from_module(&mut module, "fib", [Value::from_i32(5)])
            .expect("fail to run the target function in the module");

        println!("The result of fib(5) is {}", returns[0].to_i32());
    }
}
