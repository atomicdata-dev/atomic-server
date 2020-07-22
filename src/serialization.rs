mod serialization {
    use serde_json::from_str;

    pub fn deserialize_json_array(string: &String) -> Vec<String> {
        let vector: Vec<String> = from_str(string).unwrap();
        return vector;
    }
}
