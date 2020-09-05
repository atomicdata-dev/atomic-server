use crate::Context;
use atomic_lib::{delta::Delta, errors::AtomicResult, DeltaLine, Storelike};

/// Processes a singe delta
pub fn delta(context: &mut Context) -> AtomicResult<()> {
    let subcommand_matches = context.matches.subcommand_matches("delta").unwrap();
    let method = subcommand_to_url(context, "method")?;
    let subject = subcommand_to_url(context, "subject")?;
    let property = match subcommand_to_url(context, "property") {
        // If it's a valid URL, use that.
        Ok(prop) => Ok(prop),
        // If it's a shortname available from the Class of the resource, use that;
        Err(_) => {
            let user_arg = subcommand_matches.value_of("property").unwrap();
            context.store.property_shortname_to_url(
                &user_arg.into(),
                &context.store.get_resource_string(&subject).ok_or("Subject not found")?,
            )
        }
    };
    // If it's a valid URL, use that.
    // If it's a shortname available from the Class of the resource, use that!;
    // let property_in = subcommand_matches.value_of("value").unwrap();
    let value = subcommand_matches.value_of("value").unwrap();

    let delta = DeltaLine::new(method, subject, property?, value.into());
    let mut deltas: Vec<DeltaLine> = Vec::new();
    deltas.push(delta);
    context
        .store
        .process_delta(Delta::new_from_lines(deltas))
        .expect("Failed to apply delta");
    Ok(())
}

/// Parses a single argument (URL or Bookmark), should return a valid URL
pub fn subcommand_to_url(context: &Context, subcommand: &str) -> AtomicResult<String> {
    let subcommand_matches = context.matches.subcommand_matches("delta").unwrap();
    let user_arg = subcommand_matches.value_of(subcommand).unwrap();
    let id_url: String = context
        .mapping
        .try_mapping_or_url(&String::from(user_arg))
        .ok_or(&*format!("No url found for {}", user_arg))?;
    Ok(id_url)
}
