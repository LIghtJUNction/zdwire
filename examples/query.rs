//! Build and inspect a DNS query without performing network I/O.
use zdwire::{Class, Header, MessageBuilder, MessageView, Name, Type};

fn main() -> Result<(), zdwire::Error> {
    let name = Name::from_wire(b"\x03www\x07example\x03com\0")?;
    let mut output = [0; 512];
    let mut writer = MessageBuilder::new(&mut output, Header::new(0x1234, Header::RD))?;
    writer.add_question(name, Type::A, Class::IN)?;
    let packet = writer.finish();
    let message = MessageView::parse_strict(packet)?;
    for question in message.questions() {
        let question = question?;
        println!(
            "id={} name={} type={} bytes={}",
            message.header().id,
            question.name,
            question.qtype.0,
            packet.len()
        );
    }
    Ok(())
}
