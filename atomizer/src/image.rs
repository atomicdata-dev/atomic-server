use atomic_lib::resources::PropVals;
use exif::{In, Tag};

const DATE_TIME: &str = "date_time";

// These should map to Atomic Data Properties
fn map_tag(tag: Tag) -> String {
    match tag {
        Tag::PixelXDimension => "pixel_x_dimension",
        Tag::XResolution => "x_resolution",
        Tag::ImageDescription => "image_description",
        Tag::DateTime => DATE_TIME,
        _ => "unknown",
    }
    .to_string()
}

/// Extracts the location from an image file's EXIF data.
pub fn atomize(mut file: crate::file::File) -> PropVals {
    let mut props = PropVals::new();

    println!("Reading EXIF data from {}", file.filename());

    let mut buf_reader = std::io::BufReader::new(std::io::Cursor::new(file.bytes()));
    let exif = exif::Reader::new()
        .read_from_container(&mut buf_reader)
        .unwrap();

    let tag_list = [
        Tag::PixelXDimension,
        Tag::XResolution,
        Tag::ImageDescription,
        Tag::DateTime,
    ];

    for tag in tag_list {
        if let Some(field) = exif.get_field(tag, In::PRIMARY) {
            props.insert(
                map_tag(tag),
                atomic_lib::Value::String(field.display_value().to_string()),
            );
            println!("{}: {}", field.tag, field.display_value().with_unit(&exif));
        }
    }

    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file::File;

    #[test]
    fn load_image() {
        let f = File::open("./test/image.jpg").unwrap();
        let propvals = f.to_propvals();
        let dt = propvals.get(DATE_TIME).unwrap();
        println!("Date: {}", dt);
        assert!(dt.to_string().contains("2008"));
    }
}
