use std::time::Duration;

pub const MAX_FETCH_PAGES_PER_CHANNEL: usize = 10;

pub const SAY_COMMAND_NAME: &str = "say";
pub const SAY_MODE_SELECT_ID: &str = "say_mode";
pub const SAY_SIMPLE_PREFIX: &str = "say_simple:";
pub const SAY_EMBED_PREFIX: &str = "say_embed:";
pub const SAY_EDIT_MAIN_PREFIX: &str = "say_edit_main:";
pub const SAY_CONTENT_INPUT: &str = "say_content";
pub const SAY_TITLE_INPUT: &str = "say_title";
pub const SAY_DESCRIPTION_INPUT: &str = "say_desc";
pub const SAY_COLOR_INPUT: &str = "say_color";
pub const SAY_IMAGE_INPUT: &str = "say_image";
pub const SAY_THUMBNAIL_INPUT: &str = "say_thumb";
pub const SAY_ADD_FIELD_BUTTON: &str = "say_add_field";
pub const SAY_AUTHOR_BUTTON: &str = "say_author";
pub const SAY_FOOTER_BUTTON: &str = "say_footer";
pub const SAY_EDIT_MAIN_BUTTON: &str = "say_edit_main";
pub const SAY_SEND_BUTTON: &str = "say_send";
pub const SAY_CANCEL_BUTTON: &str = "say_cancel";
pub const SAY_FIELD_MODAL: &str = "say_field_modal";
pub const SAY_AUTHOR_MODAL: &str = "say_author_modal";
pub const SAY_FOOTER_MODAL: &str = "say_footer_modal";
pub const SAY_FIELD_NAME_INPUT: &str = "say_field_name";
pub const SAY_FIELD_VALUE_INPUT: &str = "say_field_value";
pub const SAY_FIELD_INLINE_INPUT: &str = "say_field_inline";
pub const SAY_AUTHOR_NAME_INPUT: &str = "say_author_name";
pub const SAY_AUTHOR_URL_INPUT: &str = "say_author_url";
pub const SAY_AUTHOR_ICON_INPUT: &str = "say_author_icon";
pub const SAY_FOOTER_TEXT_INPUT: &str = "say_footer_text";
pub const SAY_FOOTER_ICON_INPUT: &str = "say_footer_icon";

pub const CONTENT_LIMIT: usize = 2000;
pub const EMBED_TITLE_LIMIT: usize = 256;
pub const EMBED_FIELD_NAME_LIMIT: usize = 256;
pub const EMBED_FIELD_VALUE_LIMIT: usize = 1024;
pub const EMBED_FIELD_COUNT_LIMIT: usize = 25;
pub const EMBED_FOOTER_LIMIT: usize = 2048;
pub const EMBED_AUTHOR_LIMIT: usize = 256;
pub const EMBED_TOTAL_LIMIT: usize = 6000;
pub const MODAL_INPUT_LIMIT: u16 = 4000;
pub const URL_INPUT_LIMIT: u16 = 512;

pub const MAX_ATTACHMENT_BYTES: usize = 15 * 1024 * 1024;
pub const MAX_IMAGE_DIMENSION: u32 = 4096;
pub const MAX_DECODE_ALLOC: u64 = 64 * 1024 * 1024;
pub const MEDIA_PIPELINE_TIMEOUT: Duration = Duration::from_secs(5);
pub const CDN_ALLOWED_HOSTS: [&str; 2] = ["cdn.discordapp.com", "media.discordapp.net"];

#[derive(Clone)]
pub struct RoleGachaDrop {
	pub role_id: u64,
	pub label: &'static str,
}

#[derive(Clone)]
pub struct SpecialGachaDrop {
	pub prize: &'static str,
	pub message: &'static str,
}

pub struct GachaTier<T: 'static> {
	pub tier_name: &'static str,
	pub base_weight: u32,
	pub jitter: u32,
	pub drops: &'static [T]
}

pub const UR_SPECIAL_DROPS: &[SpecialGachaDrop] = &[
	SpecialGachaDrop { prize: "basic_nitro", message: "Yes... but I am not afraid. As long as I am with you, no matter what path it may be...
...--Therefore, please do not fear, either.
...Someday, will you expose... more of yourself to me?
<@757971702658498570>" },
];

pub const SPECIAL_GACHA_POOL: [GachaTier<SpecialGachaDrop>; 5] =[
	GachaTier { tier_name: "UR", base_weight: 5, jitter: 2, drops: UR_SPECIAL_DROPS },
	GachaTier { tier_name: "SSR", base_weight: 750, jitter: 150, drops: &[] },
	GachaTier { tier_name: "R", base_weight: 556, jitter: 80, drops: &[] },
	GachaTier { tier_name: "SR", base_weight: 191, jitter: 40, drops: &[] },
	GachaTier { tier_name: "草", base_weight: 98498, jitter: 5000, drops: &[] },
];

pub const SSR_ROLE_DROPS: &[RoleGachaDrop] = &[
	RoleGachaDrop { role_id: 1488672805024436344, label: "SS+" },
	RoleGachaDrop { role_id: 1488672138121580675, label: "SS" },
	RoleGachaDrop { role_id: 1488672215024009298, label: "S+" },
	RoleGachaDrop { role_id: 1488673139427770398, label: "S" },
	RoleGachaDrop { role_id: 1488695883892523179, label: "A+" },
	RoleGachaDrop { role_id: 1488695909301620827, label: "A" },
];

pub const UR_ROLE_DROPS: &[RoleGachaDrop] = &[
	RoleGachaDrop { role_id: 1488672177937977435, label: "UF" },
	RoleGachaDrop { role_id: 1488672678440075354, label: "UG9" },
	RoleGachaDrop { role_id: 1488672713005596682, label: "UG" },
];

pub const SR_ROLE_DROPS: &[RoleGachaDrop] = &[
	RoleGachaDrop { role_id: 1488672903468941502, label: "B" },
	RoleGachaDrop { role_id: 1488672484411703396, label: "C" },
];

pub const R_ROLE_DROPS: &[RoleGachaDrop] = &[
	RoleGachaDrop { role_id: 1488672445358411848, label: "D" },
	RoleGachaDrop { role_id: 1488673341798613022, label: "E" },
	RoleGachaDrop { role_id: 1488672878130892920, label: "F" },
	RoleGachaDrop { role_id: 1488673384777912402, label: "G" },
];

pub const ROLE_GACHA_POOL: [GachaTier<RoleGachaDrop>; 5] =[
	GachaTier { tier_name: "UR", base_weight: 5, jitter: 2, drops: UR_ROLE_DROPS },
	GachaTier { tier_name: "SSR", base_weight: 750, jitter: 150, drops: SSR_ROLE_DROPS },
	GachaTier { tier_name: "R", base_weight: 556, jitter: 80, drops: R_ROLE_DROPS },
	GachaTier { tier_name: "SR", base_weight: 191, jitter: 40, drops: SR_ROLE_DROPS },
	GachaTier { tier_name: "草", base_weight: 98498, jitter: 5000, drops: &[] },
];

pub const STICKY_MESSAGE: &str = r#"# :warning: BEFORE ASKING A QUESTION :warning:
- Having runtime errors? Install [Hachimi Edge](https://hachimi.noccu.art).
- Check for your issue in [Troubleshooting](https://hachimi.noccu.art/docs/hachimi/troubleshooting) or the [FAQ](https://hachimi.noccu.art/docs/hachimi/faqs).
- Check the pins and backread messsages in this channel.

You will be intentionally ignored if the sources mentioned above cover your issue.
Still can't find the solution for your problem? Ping the `@Helpdesk` role.
Bugs instead of tech issue? Check <#1248143380437930085>."#;