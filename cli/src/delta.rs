use crate::Context;
use atomic_lib::{delta::DeltaDeprecated, errors::AtomicResult, DeltaLine, Storelike};

/// Processes a singe delta
pub fn delta(context: &mut Context) -> AtomicResult<()> {
    let subcommand_matches = context.matches.subcommand_matches("delta").unwrap();
    let method = argument_to_url(context, "delta", "method")?;
    let subject = argument_to_url(context, "delta", "subject")?;
    let property = match argument_to_url(context, "delta", "property") {
        // If it's a valid URL, use that.
        Ok(prop) => Ok(prop),
        // If it's a shortname available from the Class of the resource, use that;
        Err(_) => {
            let shortname = subcommand_matches.value_of("property").unwrap();
            let resource = &context.store.get_resource_string(&subject)?;
            context.store.property_shortname_to_url(
                shortname,
                resource,
            )
        }
    };
    // If it's a valid URL, use that.
    // If it's a shortname available from the Class of the resource, use that!;
    // let property_in = subcommand_matches.value_of("value").unwrap();
    let value = subcommand_matches.value_of("value").unwrap();

    let delta = DeltaLine::new(method, property?, value.into());
    let mut deltas: Vec<DeltaLine> = Vec::new();
    deltas.push(delta);
    context
        .store
        .process_delta(DeltaDeprecated::new_from_lines(subject, deltas))?;
    Ok(())
}

/// Parses a single argument (URL or Bookmark), should return a valid URL
pub fn argument_to_url(context: &Context, subcommand: &str, argument: &str) -> AtomicResult<String> {
    let subcommand_matches = context.matches.subcommand_matches(subcommand).unwrap();
    let user_arg = subcommand_matches.value_of(argument).unwrap();
    let id_url: String = context
        .mapping.lock().unwrap()
        .try_mapping_or_url(&String::from(user_arg))
        .ok_or(&*format!("No url found for {}", user_arg))?;
    Ok(id_url)
}
