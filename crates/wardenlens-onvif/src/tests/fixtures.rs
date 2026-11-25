//! Synthetic replies. Addresses are 192.0.2.x / `2001:db8::` only; names are made up.

pub(crate) const NS: &str = r#"xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:tds="http://www.onvif.org/ver10/device/wsdl" xmlns:trt="http://www.onvif.org/ver10/media/wsdl" xmlns:tt="http://www.onvif.org/ver10/schema""#;

/// A SOAP 1.2 envelope around `body`.
pub(crate) fn env(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><env:Envelope {NS}><env:Body>{body}</env:Body></env:Envelope>"#
    )
}

pub(crate) fn device_info(m: &str, model: &str, fw: &str, sn: &str, hw: &str) -> String {
    env(&format!(
        "<tds:GetDeviceInformationResponse><tds:Manufacturer>{m}</tds:Manufacturer><tds:Model>{model}</tds:Model>\
         <tds:FirmwareVersion>{fw}</tds:FirmwareVersion><tds:SerialNumber>{sn}</tds:SerialNumber>\
         <tds:HardwareId>{hw}</tds:HardwareId></tds:GetDeviceInformationResponse>"
    ))
}

pub(crate) fn good_device_info() -> String {
    device_info("Acme", "Cam-1", "1.2.3", "SN0001", "HW-7")
}

pub(crate) fn profile(token: &str, name: &str, w: &str, h: &str, enc: &str) -> String {
    format!(
        r#"<trt:Profiles fixed="true" token="{token}"><tt:Name>{name}</tt:Name><tt:VideoSourceConfiguration token="vs"><tt:SourceToken>s</tt:SourceToken></tt:VideoSourceConfiguration><tt:VideoEncoderConfiguration token="ve"><tt:Name>enc</tt:Name><tt:Encoding>{enc}</tt:Encoding><tt:Resolution><tt:Width>{w}</tt:Width><tt:Height>{h}</tt:Height></tt:Resolution></tt:VideoEncoderConfiguration></trt:Profiles>"#
    )
}

pub(crate) fn profiles(list: &[String]) -> String {
    env(&format!(
        "<trt:GetProfilesResponse>{}</trt:GetProfilesResponse>",
        list.concat()
    ))
}

pub(crate) fn good_profiles() -> String {
    profiles(&[
        profile("main_tok", "Main", "2560", "1440", "H264"),
        profile("sub_tok", "Sub", "640", "360", "H264"),
    ])
}

pub(crate) fn stream_uri(uri: &str) -> String {
    env(&format!(
        "<trt:GetStreamUriResponse><trt:MediaUri><tt:Uri>{uri}</tt:Uri><tt:InvalidAfterConnect>false</tt:InvalidAfterConnect></trt:MediaUri></trt:GetStreamUriResponse>"
    ))
}

pub(crate) fn good_stream_uri() -> String {
    stream_uri("rtsp://192.0.2.10:554/stream1")
}

/// A SOAP 1.2 fault with the given subcode and text.
pub(crate) fn fault(subcode: &str, text: &str) -> String {
    env(&format!(
        "<env:Fault><env:Code><env:Value>env:Sender</env:Value><env:Subcode><env:Value>{subcode}</env:Value></env:Subcode></env:Code>\
         <env:Reason><env:Text xml:lang=\"en\">{text}</env:Text></env:Reason></env:Fault>"
    ))
}
