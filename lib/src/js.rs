#[cfg(test)]
mod test {
    use quick_js::{Context, JsValue};

    #[test]
    fn quick_js() {
        let context = Context::new().unwrap();

        // Eval.

        let value = context.eval("1 + 2").unwrap();
        assert_eq!(value, JsValue::Int(3));

        let value = context
            .eval_as::<String>(" var x = 100 + 250; x.toString() ")
            .unwrap();
        assert_eq!(&value, "350");

        // Callbacks.

        context
            .add_callback("myCallback", |a: i32, b: i32| a + b)
            .unwrap();

        context
            .eval(
                r#"
    // x will equal 30
    var x = myCallback(10, 20);
"#,
            )
            .unwrap();
    }
}
