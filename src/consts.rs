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

macro_rules! special_days {
	(
		$(
			$variant:ident => {
				occasion: $occasion:literal,
				line: $line:literal,
				dates: [$($date:expr),+ $(,)?]
			}
		),+ $(,)?
	) => {
		#[derive(Clone, Copy)]
		pub enum SpecialDay {
			$($variant,)+
		}

		impl SpecialDay {
			pub const ALL: &[SpecialDay] = &[$(Self::$variant,)+];

			pub const fn dates(self) -> &'static [(u32, u32)] {
				match self {
					$(Self::$variant => &[$($date),+],)+
				}
			}

			pub const fn occasion(self) -> &'static str {
				match self {
					$(Self::$variant => $occasion,)+
				}
			}

			pub const fn line(self) -> &'static str {
				match self {
					$(Self::$variant => $line,)+
				}
			}
		}
	};
}

special_days! {
	NewYear => {
		occasion: "New Year's Day",
		line: "Happy New Year, Trainer-san... I made a little osechi for us, packed in small bites. I... didn't cause you any trouble, did I? Spending the very first day quietly by your side makes me so happy.",
		dates: [(1, 1)]
	},
	Valentines => {
		occasion: "Valentine's Day",
		line: "Happy Valentine's Day, Trainer-san... I blended the cacao beans myself to find the right balance for your taste. Did I... get too carried away? If you wouldn't mind... please accept them.",
		dates: [(2, 14)]
	},
	UmaJpAnniversary => {
		occasion: "Umamusume JP Anniversary",
		line: "I was always all alone... supposed to quietly melt away into solitude. But you found me, Trainer-san. Thank you for never letting go of my hand, all this time.",
		dates: [(2, 24)]
	},
	WhiteDay => {
		occasion: "White Day",
		line: "A return gift...? Fufu, ordinary sweets could never repay what I gave you on Valentine's. What I'm taking in return... is you, Trainer. I'll carve my name so deeply into your chest that no one can ever steal you away, and savor you bite by bite, drop by drop, so this delicious ruin never has to end... The more I drink from you, the sweeter you become...♡",
		dates: [(3, 14)]
	},
	HachimiRelease => {
		occasion: "Hachimi's First Release",
		line: "Congratulations on this special day, Trainer-san... Thanks to what you created, even someone faint like me can be found and understood. Fufu... shall we celebrate with something sweet?",
		// https://github.com/Hachimi-Hachimi/Hachimi/releases/tag/v0.1.0
		dates: [(3, 29)]
	},
	AprilFools => {
		occasion: "April Fools' Day",
		line: "Trainer-san... even if today is a day meant for telling lies, please... never say that you will disappear. Even as a joke, my heart feels like it would tear apart...",
		dates: [(4, 1)]
	},
	Easter => {
		occasion: "Easter",
		line: "Look at all the pastel egg-shaped sweets... Searching for them quietly feels just like hide-and-seek, doesn't it? If you'd like... could we go look for them together?",
		dates: [(4, 5)]
	},
	GoldenWeek => {
		occasion: "Golden Week",
		line: "The holiday streets are so crowded and dazzling... I'm not very good with places like that. Um... if you don't mind, could we just spend the day reading side-by-side at the book cafe instead?",
		dates: [
			(4, 29),
			(4, 30),
			(5, 1),
			(5, 2),
			(5, 3),
			(5, 4),
			(5, 5),
			(5, 6)
		]
	},
	JuneBride => {
		occasion: "June Bride",
		line: "A wedding in June...? Fufu, vows spoken before a god are so fragile. Why exchange rings when I can wrap this red thread around your throat? A covenant carved into our flesh and blood... so that even when this world turns to ash, you belong solely to me. You won't object to taking me as your bride, will you?♡",
		dates: [
			(6, 7),
			(6, 8),
			(6, 9),
			(6, 10),
			(6, 11),
			(6, 12),
			(6, 13)
		]
	},
	Tanabata => {
		occasion: "Tanabata",
		line: "My wish on the tanzaku? It's always the same... 'Please give me a small corner in Trainer-san's heart... so I can protect you from the wind, and even eat up your bad dreams'...",
		dates: [(7, 7)]
	},
	MarineDay => {
		occasion: "Marine Day",
		line: "The midday sun on the beach is a bit too harsh for me... but once twilight comes and the shore empties out, would you walk along the water with me? Just the two of us...",
		dates: [(7, 20)]
	},
	Obon => {
		occasion: "Obon",
		line: "Watching the floating lanterns in the dark... it feels like I could just dissolve into the night air. But when you hold my hand like this, Trainer-san... I know that I truly exist.",
		dates: [(8, 13), (8, 14), (8, 15), (8, 16)]
	},
	UmaHalfAnniversary => {
		occasion: "Umamusume JP Half Anniversary",
		line: "Has it really only been half a year...? Your sense of time is blurring, isn't it? The red mist behind your eyes, the nausea, the urge to see only me... it's all settling in so nicely. Close your eyes and rest, Trainer-san... when you wake, I'll make sure there's nothing left in your world except my run.♡",
		dates: [(8, 24)]
	},
	Otsukimi => {
		occasion: "Otsukimi",
		line: "The ancient light is pouring in... Look at your eyes, Trainer-san. Red, like blood... matching. Don't try to pull away now... the blood has already mingled too deeply. If you leave, your vessel will just shatter into pieces. We're going to devour the moon together... forever... and ever...♡",
		dates: [(9, 15)]
	},
	SportsDay => {
		occasion: "Sports Day",
		line: "I slipped past the defenders in their blind spots again... Did you see me? I don't care if no one else noticed... as long as you were watching from the stands, that's all that matters.",
		dates: [(10, 12)]
	},
	Halloween => {
		occasion: "Halloween",
		line: "Trick or treat...? Fufu... one, two, three... seven pieces of meat on the track tonight. But none of them have a soul as sweet as yours. Why are you shaking? You're the one who let this monster inside. Now come... let me drink until every last drop runs completely dry.♡",
		dates: [(10, 31)]
	},
	LaborThanksgiving => {
		occasion: "Labor Thanksgiving Day",
		line: "You've worked so hard for my sake, Trainer-san. Today, please just rest... I ground fresh Guatemala beans and baked some apple cookies to go with your coffee.",
		dates: [(11, 23)]
	},
	ChristmasEve => {
		occasion: "Christmas Eve",
		line: "Snow is beginning to fall... Just like the scene in that movie I saw long ago. Trainer-san... as a memory just between the two of us, would you... dance with me in the snow?",
		dates: [(12, 24)]
	},
	Christmas => {
		occasion: "Christmas",
		line: "Merry Christmas, Trainer-san... Santa Claus doesn't visit dying people in hospital rooms like this, but we never needed an ordinary miracle anyway. Look at me... my only gift is a piece of my heart, buried deep inside your chest. I'll eat up all your bad dreams, blot out the morning light, and slowly consume whatever reason you have left. There's no escaping each other now... foreeever...♡",
		dates: [(12, 25)]
	},
}

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