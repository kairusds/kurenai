use std::time::Duration;

pub const VOICE_INDEX_PATH: &str = "snd_voi/files.json";
pub const VOICE_DIR: &str = "snd_voi";
pub const DATA_DB_PATH: &str = "data.db";
pub const BIRTHDAY_COMMAND_NAME: &str = "birthday";
pub const STILL_BIRTHDAY_MONTH: u32 = 5;
pub const STILL_BIRTHDAY_DAY: u32 = 2;

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

impl SpecialDay {
	pub const fn seasonal_voice_paths(self) -> &'static [&'static str] {
		match self {
			Self::NewYear => &["snd_voi_home_109700/snd_voi_home_109700_0003.m4a"],
			Self::Valentines => &[
				"snd_voi_home_109700/snd_voi_home_109700_0004.m4a",
				"snd_voi_home_109700/snd_voi_home_109700_0005.m4a",
				"snd_voi_valentine_109700_0001.m4a",
			],
			Self::Tanabata => &["snd_voi_home_109700/snd_voi_home_109700_0006.m4a"],
			Self::Otsukimi => &["snd_voi_home_109701/snd_voi_home_109701_0004.m4a"],
			Self::Halloween => &["snd_voi_home_109700/snd_voi_home_109700_0007.m4a"],
			Self::ChristmasEve | Self::Christmas => &[
				"snd_voi_home_109700/snd_voi_home_109700_0008.m4a",
				"snd_voi_home_109700/snd_voi_home_109700_0009.m4a",
			],
			_ => &[],
		}
	}
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
	RoleGachaDrop { role_id: 1555803546417496075, label: "UE" },
	RoleGachaDrop { role_id: 1555802307688398878, label: "UF9" },
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum VoiceCategory {
	General,
	TimeBased { start_hour: u32, end_hour: u32 },
	Bond { level: u8 },
	StillBirthday,
	TrainerBirthday,
	Seasonal,
}

#[derive(Clone, Copy)]
pub struct VoiceLine {
	pub path: &'static str,
	pub translation: Option<&'static str>,
	pub category: VoiceCategory,
}

macro_rules! voice_lines {
	(
		$(
			{
				path: $path:literal,
				translation: $translation:expr,
				category: $category:expr $(,)?
			}
		),+ $(,)?
	) => {
		pub const VOICE_LINES: &[VoiceLine] = &[
			$(
				VoiceLine {
					path: $path,
					translation: $translation,
					category: $category,
				},
			)+
		];
	};
}

voice_lines! {
	{
		path: "snd_sfx_cti_crd109701_001_lng.m4a",
		translation: None,
		category: VoiceCategory::General,
	},
	{
		path: "snd_sfx_cti_crd109701_001_srt.m4a",
		translation: None,
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_aimteam_109700_0000.m4a",
		translation: Some("Good work today."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_gacha_109701_0000.m4a",
		translation: Some("I can't hold back... Let me savor it! Everything you have!"),
		category: VoiceCategory::Bond { level: 3 },
	},
	{
		path: "snd_voi_valentine_109700_0001.m4a",
		translation: Some("Happy Valentine's Day... *hehe*"),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_collectraid_109700/snd_voi_collectraid_109700_0004.m4a",
		translation: Some("To help grow our channel subscribers, please lend us your support. If my voice is reaching you..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_collectraid_109700/snd_voi_collectraid_109700_0005.m4a",
		translation: Some("Thank you very much for your cooperation. Please accept and keep this reward for reaching our goal."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0000.m4a",
		translation: Some("You granted me a blessing. Nowhere but by your side can I feel happiness. An eternal, sweet blessing..."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0001.m4a",
		translation: Some("You, who accept all of my fierceness and ugliness, are my sunlit spot... and my comforting twilight."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0002.m4a",
		translation: Some("I want to know you more and more. Your unseen depths... Someday, I want to be swallowed into the abyss of your heart too."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0003.m4a",
		translation: Some("Happy New Year. I ask for nothing special—so long as this becomes a year where I can quietly stay close to you."),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0004.m4a",
		translation: Some("Even though I should be used to making sweets, my hands somehow grew feverish... Could it be because this chocolate is for you?"),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0005.m4a",
		translation: Some("I may have made this chocolate a little too sweet. When I thought about making a flavor that would linger in your memories forever... I couldn't help it."),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0006.m4a",
		translation: Some("I'm a little envious of Orihime. If the time you can meet your beloved is short, you can show them only your beautiful side, right?"),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0007.m4a",
		translation: Some("Being played a prank on once in a while is fun too, but being able to hand out delicious sweets to everyone is more wonderful than anything."),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0008.m4a",
		translation: Some("A job delivering presents might suit me well. Even when I enter a room, people rarely notice me."),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0009.m4a",
		translation: Some("Back home, making the Christmas cake was my role. Being able to do something for one's family... it's a happy thing, isn't it?"),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0010.m4a",
		translation: Some("I've already finished cleaning the Trainer's room. ...Hehe, had you noticed?"),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0011.m4a",
		translation: Some("There are so many cake shops I want to recommend... Um, if it's alright with you, I was hoping we could go choose together."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0012.m4a",
		translation: Some("What kind of person were you when you were little, who did you meet, and what did you learn...? If you'd like, please tell me your story."),
		category: VoiceCategory::TrainerBirthday,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0013.m4a",
		translation: Some("The veil my parents gave me for my birthday because I'm sensitive to sunlight. I've replaced it a few times, but the memories are eternal."),
		category: VoiceCategory::StillBirthday,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0014.m4a",
		translation: Some("On my birthday, I end up thinking about the nature I was born with. Yet it's no longer painful... because you are here."),
		category: VoiceCategory::StillBirthday,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0015.m4a",
		translation: Some("A notice has arrived for you. Shall we open it together?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0016.m4a",
		translation: Some("It looks like a gift has arrived. Opening it will be something to look forward to, won't it? *hehe*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0017.m4a",
		translation: Some("It seems there are completed missions. Well done."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0018.m4a",
		translation: Some("An event is apparently being held. That girl... is starting to grow restless too."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0019.m4a",
		translation: Some("The event seems to be thriving. I must be careful not to get too absorbed and show an unseemly side of myself."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0021.m4a",
		translation: Some("Tonight too, the time to sharpen my fangs arrives..."),
		category: VoiceCategory::TimeBased { start_hour: 18, end_hour: 4 },
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0022.m4a",
		translation: Some("The academy's historical tales make my heart leap."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0023.m4a",
		translation: Some("A race...? Delicious opponents in broad daylight..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0024.m4a",
		translation: Some("It seems the Umamusume Archive level has gone up."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0025.m4a",
		translation: Some("Dark colors gather sunlight and protect the skin. This outfit is a very dependable partner... isn't it?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0026.m4a",
		translation: Some("I looked for clothes as long-hemmed as possible. Clothes that are easy to run in might wake \"that girl\" up, after all."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109700/snd_voi_home_109700_0027.m4a",
		translation: Some("This outfit, a basket with sweets and coffee, and a parasol. My three-piece set for days off. *hehe*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0000.m4a",
		translation: Some("Good morning. Being able to see you from the morning makes me feel as though even the shadows in my heart are illuminated."),
		category: VoiceCategory::TimeBased { start_hour: 5, end_hour: 10 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0001.m4a",
		translation: Some("Ah... the sunlight has gotten stronger. I might want to step back into the shade for a bit."),
		category: VoiceCategory::TimeBased { start_hour: 11, end_hour: 13 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0002.m4a",
		translation: Some("A timer is essential for lunch. Otherwise, break time ends while I'm still savoring every bite."),
		category: VoiceCategory::TimeBased { start_hour: 11, end_hour: 13 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0003.m4a",
		translation: Some("I made some snacks, so please have some if you'd like. If they suit your taste, I'll be very happy."),
		category: VoiceCategory::TimeBased { start_hour: 14, end_hour: 17 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0004.m4a",
		translation: Some("I want to quietly gaze at the ever-changing moon with you, though a full moon alone... might awaken \"that girl.\""),
		category: VoiceCategory::Seasonal,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0005.m4a",
		translation: Some("The night is kind. Even things you don't want seen are hidden by the veil of darkness."),
		category: VoiceCategory::TimeBased { start_hour: 18, end_hour: 4 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0006.m4a",
		translation: Some("The cycle of the four seasons begins anew. No matter how many times the seasons turn, is there a place for me in your heart?"),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0007.m4a",
		translation: Some("I'll avoid standing carelessly in dark places for a while. Um... especially during test-of-courage season, I'm easily mistaken for a ghost."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0008.m4a",
		translation: Some("Autumn is short, isn't it? There are so many flavorful things that the season ends while I'm still savoring them on my tongue."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0009.m4a",
		translation: Some("Aha... I'm not cold. Just looking at your face warms my body."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0010.m4a",
		translation: Some("It's troubling. Every time I see Ramonu-san, something scorches my heart with a sizzle... Ah, just remembering it... again..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0011.m4a",
		translation: Some("When I look up at the stars with Universe-san, I feel as if I'm melting into the twinkling sky—it's soothing."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0012.m4a",
		translation: Some("Tomatel Amaryllis! ...*hehe*, it's a spell Sweep-san came up with to make tomato juice taste better."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0013.m4a",
		translation: Some("Sweet confections and strong coffee. Magical tools indispensable for wonderful hospitality... aren't they? *hehe*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0014.m4a",
		translation: Some("I love letting my heart wander in daydreams across a sea of books. Historical novels in particular carry me away to ancient eras."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0015.m4a",
		translation: Some("Taking center stage is bashful, but I have to carry myself with poise, don't I? So that everyone who came can enjoy themselves."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0016.m4a",
		translation: Some("If an outfit is this glamorous, will it conceal... what lies deep within me?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0017.m4a",
		translation: Some("No! Wearing an outfit like this in a place like this... Ah, I can't... hold it back anymore..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0018.m4a",
		translation: Some("A vivid, eye-opening crimson. It's almost as if it reflects \"that girl's\" heart... isn't it?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0019.m4a",
		translation: Some("I like cleaning in the morning. It feels like my heart is purified at the start of the day too."),
		category: VoiceCategory::TimeBased { start_hour: 5, end_hour: 10 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0020.m4a",
		translation: Some("Once, when I stepped into the shade for a while, it turned into a missing-person case without my knowing... Having such a faint presence is quite a problem."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0021.m4a",
		translation: Some("At night, my figure melts into the darkness. Shall I keep singing so you know where I am? La~ la~..."),
		category: VoiceCategory::TimeBased { start_hour: 18, end_hour: 4 },
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0022.m4a",
		translation: Some("Spring is a season filled with the voices of all kinds of life. Both long-lived and short-lived creatures feel equally dear to me."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0023.m4a",
		translation: Some("I've soiled these hands again... Um, I let the popsicle melt before I could finish eating it."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0024.m4a",
		translation: Some("Red spider lilies are beautiful, yet poisonous. Perhaps that beauty too is a guise desperately put on to hide what lies within."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_home_109701/snd_voi_home_109701_0025.m4a",
		translation: Some("Snow is lovely. Endlessly white and pure... Perhaps this feeling is... longing."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_live_109700/snd_voi_live_109700_0000.m4a",
		translation: Some("If I can add a touch of grace to the stage."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_live_109700/snd_voi_live_109700_0001.m4a",
		translation: Some("*Hehe*... To a dazzling banquet."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0001.m4a",
		translation: Some("I can no longer imagine myself without you. Perhaps I was the one whose soul was devoured back then."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0003.m4a",
		translation: Some("With you, I'll go anywhere."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0004.m4a",
		translation: Some("So that I may meet your expectations."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0005.m4a",
		translation: Some("To be of even greater help to you."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0006.m4a",
		translation: Some("I'm off."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0007.m4a",
		translation: Some("I have returned."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0011.m4a",
		translation: Some("Boiling... burning... *hah!*"),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0016.m4a",
		translation: Some("My heart tightens with resolve—so that I don't show an unseemly side."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0017.m4a",
		translation: Some("The school uniform puts me at ease. I don't like standing out individually."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0020.m4a",
		translation: Some("It's such a lovely outfit, it makes me feel bashful."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0021.m4a",
		translation: Some("A warm smile for the fans, right?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0022.m4a",
		translation: Some("May this form become your pride."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0023.m4a",
		translation: Some("Here, I must hide it... my base, ugly nature."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0026.m4a",
		translation: Some("No matter how many guises I wear, what lurks inside never changes."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0027.m4a",
		translation: Some("Clothes are a mirror reflecting oneself. How do I look to you now?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0042.m4a",
		translation: Some("Casual clothes in a place like this... I feel like I've become a delinquent."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109700/snd_voi_outgame_109700_0043.m4a",
		translation: Some("If you have time, how about a stroll outside?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_outgame_109701/snd_voi_outgame_109701_0000.m4a",
		translation: Some("So that I can... devour even more..."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_outgame_109701/snd_voi_outgame_109701_0001.m4a",
		translation: Some("Feed me until I'm completely full!"),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_outgame_109701/snd_voi_outgame_109701_0003.m4a",
		translation: Some("I'm Still in Love. Are you going to set me free?"),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0000.m4a",
		translation: Some("*Hehe*... So next time you intend to devour me to the very end."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0001.m4a",
		translation: Some("My legs are trembling... I haven't had enough of running wild yet."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0002.m4a",
		translation: Some("Nowhere near enough to eat..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0003.m4a",
		translation: Some("If \"that girl\" doesn't go feral, this is all I amount to..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0006.m4a",
		translation: Some("Give it to me, give it to me!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0008.m4a",
		translation: Some("Thank you for a good match. Thank you for the sweet soul."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0009.m4a",
		translation: Some("I can't hold back...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0010.m4a",
		translation: Some("Impossible to hold back...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0011.m4a",
		translation: Some("Mine!"),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_race_109700/snd_voi_race_109700_0012.m4a",
		translation: Some("So fun, so much fun!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_race_109701/snd_voi_race_109701_0000.m4a",
		translation: Some("A wonderful full-course meal... I enjoyed it down to the very last drop."),
		category: VoiceCategory::Bond { level: 3 },
	},
	{
		path: "snd_voi_race_109701/snd_voi_race_109701_0002.m4a",
		translation: Some("Give me everything of yours!"),
		category: VoiceCategory::Bond { level: 3 },
	},
	{
		path: "snd_voi_race_109701/snd_voi_race_109701_0003.m4a",
		translation: Some("Ah, how beautiful... Everything, everything, everything... I want to devour it all!"),
		category: VoiceCategory::Bond { level: 3 },
	},
	{
		path: "snd_voi_story_00000_01_1097001/snd_voi_story_00000_01_1097001_00.m4a",
		translation: Some("Today's mock race was wonderful. Clashing earnestly with everything they had..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097001/snd_voi_story_00000_01_1097001_01.m4a",
		translation: Some("Everyone baring their instincts and devouring one another... Ah, just watching it makes me...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097001/snd_voi_story_00000_01_1097001_02.m4a",
		translation: Some("Ah... Oh no, I'm doing it again...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097001/snd_voi_story_00000_01_1097001_03.m4a",
		translation: Some("Ugh... Stay rational... stay sensible... Don't... come out..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097001/snd_voi_story_00000_01_1097001_04.m4a",
		translation: Some("*Haa*... It... subsided..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097001/snd_voi_story_00000_01_1097001_05.m4a",
		translation: Some("No good—after a race, I really have to find somewhere I can be alone."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097002/snd_voi_story_00000_01_1097002_00.m4a",
		translation: Some("Trainer-san, might you be tired?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097002/snd_voi_story_00000_01_1097002_01.m4a",
		translation: Some("If chocolate is alright, shall I bring some? It might offer a little comfort."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097002/snd_voi_story_00000_01_1097002_02.m4a",
		translation: Some("You may think it's just a sweet, but chocolate is truly amazing."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097002/snd_voi_story_00000_01_1097002_03.m4a",
		translation: Some("Just taking a bite lets sweetness soak through your whole body, soothing your thirst and filling the deepest parts of your heart."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097002/snd_voi_story_00000_01_1097002_04.m4a",
		translation: Some("A euphoria like finding what you've been searching for, like meeting your destined person..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097002/snd_voi_story_00000_01_1097002_05.m4a",
		translation: Some("O-or something like that... I hope you feel fulfilled too, Trainer-san."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097003/snd_voi_story_00000_01_1097003_00.m4a",
		translation: Some("U-um... unless I'm mistaken, were you looking for me?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097003/snd_voi_story_00000_01_1097003_01.m4a",
		translation: Some("I thought so... I'm sorry, I have such a faint presence."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097003/snd_voi_story_00000_01_1097003_02.m4a",
		translation: Some("Oh, please don't worry about it. It happens all the time."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097003/snd_voi_story_00000_01_1097003_03.m4a",
		translation: Some("Automatic doors not opening, being skipped in line... it's genuinely an everyday occurrence."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097003/snd_voi_story_00000_01_1097003_04.m4a",
		translation: Some("To stay inconspicuous, to stay out of everyone's sight... because that's my wish too."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_01_1097003/snd_voi_story_00000_01_1097003_05.m4a",
		translation: Some("Even if you can't find me, I will find you. So it's alright... Trainer-san."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_story_00000_02_1097001/snd_voi_story_00000_02_1097001_00.m4a",
		translation: Some("Aruvu-san, you're rarely startled even when I speak to you."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097001/snd_voi_story_00000_02_1097001_02.m4a",
		translation: Some("Ah, um... I'm a bit hard for everyone to notice... so people usually think I called out to them out of nowhere."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097001/snd_voi_story_00000_02_1097001_04.m4a",
		translation: Some("I-is that so?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097001/snd_voi_story_00000_02_1097001_05.m4a",
		translation: Some("I wonder if Aruvu-san has sharper senses than others, and that's why they happened to notice..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097001/snd_voi_story_00000_02_1097001_07.m4a",
		translation: Some("Aruvu-san?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097001/snd_voi_story_00000_02_1097001_10.m4a",
		translation: Some("Y-you mustn't... do something like that. It's far too unseemly..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097002/snd_voi_story_00000_02_1097002_00.m4a",
		translation: Some("Um... thank you for the haskap sweets the other day. They were very delicious."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097002/snd_voi_story_00000_02_1097002_02.m4a",
		translation: Some("Yes! The tartness was just right... Only, I couldn't eat them very neatly—I shouldn't have eaten them with my hands."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097002/snd_voi_story_00000_02_1097002_04.m4a",
		translation: Some("I feel like... a sweet scent still lingers on my fingertips."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097002/snd_voi_story_00000_02_1097002_05.m4a",
		translation: Some("Huh?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097002/snd_voi_story_00000_02_1097002_06.m4a",
		translation: Some("*Sigh*... It's embarrassing to remember. Jam got on my lips, so I licked it off with my tongue over and over, yet..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097002/snd_voi_story_00000_02_1097002_07.m4a",
		translation: Some("Even then I couldn't get it all off, and sweet jam got on my fingers and palms too..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097002/snd_voi_story_00000_02_1097002_08.m4a",
		translation: Some("Ah, yet that rich aroma... I don't think I'll ever forget the luscious taste lingering in my mouth."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_00000_02_1097002/snd_voi_story_00000_02_1097002_10.m4a",
		translation: Some("Yes, I'm looking forward to it. *hehe*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_00.m4a",
		translation: Some("*Hehe*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_01.m4a",
		translation: Some("*Ahahaha...!*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_02.m4a",
		translation: Some("*Hehe*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_03.m4a",
		translation: Some("*Hmph* / *Heh*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_04.m4a",
		translation: Some("*Haa...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_05.m4a",
		translation: Some("We did it! / I did it!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_06.m4a",
		translation: Some("I can't resist...! / It's unbearable...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_07.m4a",
		translation: Some("My..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_08.m4a",
		translation: Some("Oh, my"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_09.m4a",
		translation: Some("I see"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_10.m4a",
		translation: Some("I'll do my best"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_100.m4a",
		translation: Some("Ugh..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_101.m4a",
		translation: Some("No... / It's no good..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_102.m4a",
		translation: Some("You mustn't / That won't do"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_103.m4a",
		translation: Some("No / Don't"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_104.m4a",
		translation: Some("Please... *Uwaaaah!*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_105.m4a",
		translation: Some("*Uhaa...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_106.m4a",
		translation: Some("*Achoo!*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_107.m4a",
		translation: Some("*Nn...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_108.m4a",
		translation: Some("I've decided"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_109.m4a",
		translation: Some("*Hah...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_11.m4a",
		translation: Some("It's wonderful"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_110.m4a",
		translation: Some("Amazing"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_111.m4a",
		translation: Some("It's wonderful"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_112.m4a",
		translation: Some("Amazing..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_113.m4a",
		translation: Some("I won't lose"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_114.m4a",
		translation: Some("I won't lose..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_115.m4a",
		translation: Some("Now, bare it all...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_116.m4a",
		translation: Some("I thank you"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_117.m4a",
		translation: Some("Please do your best"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_118.m4a",
		translation: Some("Do your best"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_119.m4a",
		translation: Some("Please do your best! Do your best!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_12.m4a",
		translation: Some("*Hmph... haaah!*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_120.m4a",
		translation: Some("*Haaah!*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_121.m4a",
		translation: Some("Good work"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_122.m4a",
		translation: Some("Good work"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_123.m4a",
		translation: Some("Congratulations"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_124.m4a",
		translation: Some("Thank you very much"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_125.m4a",
		translation: Some("Congratulations. Congratulations."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_126.m4a",
		translation: Some("Congratulations!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_127.m4a",
		translation: Some("Happy New Year"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_128.m4a",
		translation: Some("Happy Valentine's"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_129.m4a",
		translation: Some("*Hehe...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_13.m4a",
		translation: Some("Merry Christmas"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_130.m4a",
		translation: Some("Happy Birthday"),
		category: VoiceCategory::TrainerBirthday,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_131.m4a",
		translation: Some("I'm off"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_132.m4a",
		translation: Some("I'm heading out"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_133.m4a",
		translation: Some("I have returned"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_134.m4a",
		translation: Some("*Hehehe...* I'm back"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_135.m4a",
		translation: Some("Thank you"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_136.m4a",
		translation: Some("Thank you..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_137.m4a",
		translation: Some("I'm sorry"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_138.m4a",
		translation: Some("Please"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_139.m4a",
		translation: Some("Good morning"),
		category: VoiceCategory::TimeBased { start_hour: 5, end_hour: 10 },
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_14.m4a",
		translation: Some("Hello"),
		category: VoiceCategory::TimeBased { start_hour: 11, end_hour: 13 },
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_140.m4a",
		translation: Some("Goodbye"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_141.m4a",
		translation: Some("Yeah / Mhm"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_142.m4a",
		translation: Some("Mhm!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_143.m4a",
		translation: Some("*Hmm...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_144.m4a",
		translation: Some("Hmm?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_145.m4a",
		translation: Some("Yeah"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_146.m4a",
		translation: Some("Mhm"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_147.m4a",
		translation: Some("*Hmm...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_148.m4a",
		translation: Some("Yeah"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_149.m4a",
		translation: Some("Hey"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_15.m4a",
		translation: Some("Hey..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_150.m4a",
		translation: Some("Um..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_151.m4a",
		translation: Some("*Kuh...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_152.m4a",
		translation: Some("*Uuu...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_153.m4a",
		translation: Some("*Kuh...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_154.m4a",
		translation: Some("*Ugh...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_155.m4a",
		translation: Some("Oh my"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_156.m4a",
		translation: Some("Jeez..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_157.m4a",
		translation: Some("*Uuu...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_16.m4a",
		translation: Some("I'm terribly sorry"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_17.m4a",
		translation: Some("*Kyah!*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_18.m4a",
		translation: Some("Huh?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_19.m4a",
		translation: Some("My"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_20.m4a",
		translation: Some("*Uuu...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_21.m4a",
		translation: Some("*Phew...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_22.m4a",
		translation: Some("Oh my, what a thing..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_23.m4a",
		translation: Some("What's the matter?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_24.m4a",
		translation: Some("Please stop...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_25.m4a",
		translation: Some("Um..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_26.m4a",
		translation: Some("*Hmm...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_27.m4a",
		translation: Some("What should I do..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_28.m4a",
		translation: Some("Yes, I see / Is that so"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_29.m4a",
		translation: Some("Please (formal)"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_30.m4a",
		translation: Some("*Haa...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_31.m4a",
		translation: Some("*Haa...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_32.m4a",
		translation: Some("*Haa...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_33.m4a",
		translation: Some("Good morning"),
		category: VoiceCategory::TimeBased { start_hour: 5, end_hour: 10 },
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_34.m4a",
		translation: Some("Hello"),
		category: VoiceCategory::TimeBased { start_hour: 11, end_hour: 13 },
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_35.m4a",
		translation: Some("Good evening"),
		category: VoiceCategory::TimeBased { start_hour: 18, end_hour: 4 },
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_36.m4a",
		translation: Some("Excuse me"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_37.m4a",
		translation: Some("Thank you for the meal"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_38.m4a",
		translation: Some("Thank you for the meal"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_39.m4a",
		translation: Some("Yes"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_40.m4a",
		translation: Some("Yes, yes..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_41.m4a",
		translation: Some("No"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_42.m4a",
		translation: Some("No..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_43.m4a",
		translation: Some("Um..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_44.m4a",
		translation: Some("U-um..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_45.m4a",
		translation: Some("Excuse me / I'm sorry"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_46.m4a",
		translation: Some("Trainer-san"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_47.m4a",
		translation: Some("Trainer-san"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_48.m4a",
		translation: Some("Trainer-san"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_49.m4a",
		translation: Some("*Haa...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_50.m4a",
		translation: Some("*Phew...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_51.m4a",
		translation: Some("*Haa...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_52.m4a",
		translation: Some("*Aah...* So fun..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_53.m4a",
		translation: Some("Even though... I shouldn't..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_54.m4a",
		translation: Some("Rationally... sensibly..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_55.m4a",
		translation: Some("*Kuh...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_56.m4a",
		translation: Some("I'm terribly sorry"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_57.m4a",
		translation: Some("No way... / How could that be..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_58.m4a",
		translation: Some("Trainer-san... Trainer-san..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_59.m4a",
		translation: Some("Mhm"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_60.m4a",
		translation: Some("Um..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_61.m4a",
		translation: Some("Here I go / I'm ready"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_62.m4a",
		translation: Some("Please (formal)"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_63.m4a",
		translation: Some("Yes... *hehe*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_64.m4a",
		translation: Some("*Ufufu*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_65.m4a",
		translation: Some("Ah..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_66.m4a",
		translation: Some("Ah...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_67.m4a",
		translation: Some("Ugh..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_68.m4a",
		translation: Some("That's right"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_69.m4a",
		translation: Some("Yes"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_70.m4a",
		translation: Some("Yeah"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_71.m4a",
		translation: Some("Huh?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_72.m4a",
		translation: Some("Yes..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_73.m4a",
		translation: Some("Uh"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_74.m4a",
		translation: Some("*Hmm...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_75.m4a",
		translation: Some("Um..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_76.m4a",
		translation: Some("And then..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_77.m4a",
		translation: Some("However..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_78.m4a",
		translation: Some("In that case..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_79.m4a",
		translation: Some("Um..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_80.m4a",
		translation: Some("Well..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_81.m4a",
		translation: Some("Now / Well then"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_82.m4a",
		translation: Some("Now..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_83.m4a",
		translation: Some("Now... now!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_84.m4a",
		translation: Some("Please / Go ahead"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_85.m4a",
		translation: Some("Let's go"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_86.m4a",
		translation: Some("Let's go"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_87.m4a",
		translation: Some("Let's go"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_88.m4a",
		translation: Some("Let's go"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_89.m4a",
		translation: Some("Now, let's be off"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_90.m4a",
		translation: Some("Let's go"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_91.m4a",
		translation: Some("You mustn't"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_92.m4a",
		translation: Some("Ah"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_93.m4a",
		translation: Some("*Nn*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_94.m4a",
		translation: Some("*Hmph*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_95.m4a",
		translation: Some("*Haah*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_96.m4a",
		translation: Some("*Ei!*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_97.m4a",
		translation: Some("*Kuh...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_98.m4a",
		translation: Some("Ah"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_story_051097001/snd_voi_story_051097001_99.m4a",
		translation: Some("Ugh..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_tc_1097/snd_voi_cygames_1097.m4a",
		translation: Some("Cygames"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_tc_1097/snd_voi_title_1097.m4a",
		translation: Some("Umamusume: Pretty Derby"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_teamst_109700/snd_voi_teamst_109700_0000.m4a",
		translation: Some("Ah, it's coming out..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_teamst_109700/snd_voi_teamst_109700_0001.m4a",
		translation: Some("Thank you for the feast."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_teamst_109700/snd_voi_teamst_109700_0002.m4a",
		translation: Some("Not enough, not enough!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_teamst_109700/snd_voi_teamst_109700_0003.m4a",
		translation: Some("I let them get away..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_teamst_109700/snd_voi_teamst_109700_0004.m4a",
		translation: Some("My stomach is full..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_teamst_109700/snd_voi_teamst_109700_0005.m4a",
		translation: Some("Ah, the supreme taste..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_title_109700/snd_voi_title_109700_0000.m4a",
		translation: Some("Cygames"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_title_109700/snd_voi_title_109700_0001.m4a",
		translation: Some("Umamusume: Pretty Derby"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_title_109700/snd_voi_title_109700_0004.m4a",
		translation: Some("Today's login bonus appears to be this."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_title_109700/snd_voi_title_109700_0005.m4a",
		translation: Some("Tomorrow, it seems we can receive this."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0000.m4a",
		translation: Some("If \"that girl\" starts raging right now, I don't feel like my legs will hold up."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0001.m4a",
		translation: Some("My body won't listen to me... I'm terribly sorry for disappointing you."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0002.m4a",
		translation: Some("I've had enough of waiting... Now...! No, it's still too soon..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0003.m4a",
		translation: Some("My legs want to run... Ah, I think I can understand \"that girl's\" feelings a little right now."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0004.m4a",
		translation: Some("I'm watching. A body capable of letting \"that girl\" devour everything... I'm waiting for it to be completed."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0005.m4a",
		translation: Some("Even during warm-ups, my body aches with anticipation... I have to run soon... Soon, soon, soon...!"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0006.m4a",
		translation: Some("Let's proceed quietly with preparations. The more we build up, the wilder \"that girl\" will rage on the turf."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0007.m4a",
		translation: Some("Together with you, let's tame what lies within—until the moment we set it free."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0008.m4a",
		translation: Some("I don't feel the usual surge today... \"That girl\" is unusually quiet."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0009.m4a",
		translation: Some("I have to pull myself together, don't I? Times like this call for bitter coffee... perhaps."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0010.m4a",
		translation: Some("My legs aren't trembling, my chest doesn't ache... Do I not desire to run...?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0011.m4a",
		translation: Some("I'm terribly sorry. Might I rest in the shade for a little while?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0012.m4a",
		translation: Some("Aren't we letting \"that girl\" run a bit too wild...? If I lose the means to control her, what might happen..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0013.m4a",
		translation: Some("I'm starting to lose track... The raging monster, the me trying to hold her back... Which one is the real me... *ahaha*... which?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0014.m4a",
		translation: Some("I'm parched... hopelessly starving... Ah, the chains binding \"that girl\" will snap any moment now..."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0015.m4a",
		translation: Some("It's okay, you don't have to anymore. Really...? *Hehe... ahahaha!* I don't have to hold back anymore...!"),
		category: VoiceCategory::Bond { level: 3 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0016.m4a",
		translation: Some("Surely I won't be able to hold it back today. Even if I expose my base, ugly form... will you alone accept me?"),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0017.m4a",
		translation: Some("It's strange. It should be frightening, yet walking with you makes my steps feel light. Let's go together."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0018.m4a",
		translation: Some("Can I eat now? As much as I want...! *Hehe... ahahahaha!*"),
		category: VoiceCategory::Bond { level: 3 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0019.m4a",
		translation: Some("Ah, I must say thank you—for inviting me to such a wonderful banquet crowded with delicacies."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0020.m4a",
		translation: Some("These honed legs are my weapon—that girl's fangs. I will definitely take first place and return to you."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0021.m4a",
		translation: Some("Perhaps the two of us have been raising a monster together. Even so, I don't mind... if it brings you victory."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0022.m4a",
		translation: Some("I wonder if there's one here... A strong girl, a fast girl, a delicious girl... *haa...*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0023.m4a",
		translation: Some("Are you worried about me? It's alright—that girl hasn't lost her fangs either."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0024.m4a",
		translation: Some("I—we will fight. Even if I cannot believe in myself, I can believe in you."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0025.m4a",
		translation: Some("Please don't worry. I will prove the righteousness of everything you've done for me."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0026.m4a",
		translation: Some("With you, there is nothing to fear. Even if what awaits us... is the abyss."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0027.m4a",
		translation: Some("Would you take my hand? If you do, I'm sure the trembling will stop too."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0028.m4a",
		translation: Some("\"That girl\" has lost her strength... Then I have no choice but to pull it off on my own."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0029.m4a",
		translation: Some("Well then, I'm off."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0030.m4a",
		translation: Some("*Hehe*... Now then."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0031.m4a",
		translation: Some("Ah... oh my?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0032.m4a",
		translation: Some("Together with you."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0033.m4a",
		translation: Some("Pretty..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0034.m4a",
		translation: Some("Ah..."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0037.m4a",
		translation: Some("*Hehe*"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0038.m4a",
		translation: Some("Well then"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0039.m4a",
		translation: Some("What intense sunlight... Um, for a little while, may I intrude upon your shadow?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0040.m4a",
		translation: Some("My legs are trembling... I wonder if \"that girl\" likes the sea too—or perhaps it's because she can sharpen her fangs even keener here."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0041.m4a",
		translation: Some("All kinds of stalls are lined up over there. I wonder if there's a tomato juice stall."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0063.m4a",
		translation: Some("Right by your side is where our happiness truly was."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0064.m4a",
		translation: Some("Thank you very much for taking care of me."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109700/snd_voi_training_109700_0065.m4a",
		translation: Some("Yes, if I'm good enough for you."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0000.m4a",
		translation: Some("Embarrassingly, even while waiting for you my heart was pounding restlessly... *hehe*, shall we begin then?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0001.m4a",
		translation: Some("Polishing my legs, sharpening my fangs—all for that moment when everything is unleashed."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0002.m4a",
		translation: Some("Ah... my blood is boiling... *hehe*... What is today's offering?"),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0003.m4a",
		translation: Some("I must train with the utmost care—so as not to get in anyone's way, and so as not to boil over too much."),
		category: VoiceCategory::General,
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0005.m4a",
		translation: Some("You can tame us... me, and the one who dwells inside me."),
		category: VoiceCategory::Bond { level: 1 },
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0006.m4a",
		translation: Some("You are as dazzling as the sun, yet being burned by you feels so comforting."),
		category: VoiceCategory::Bond { level: 2 },
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0007.m4a",
		translation: Some("I will entrust everything to you. Whether ascending or falling... we will be together forever."),
		category: VoiceCategory::Bond { level: 3 },
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0008.m4a",
		translation: Some("Whether ascending or falling, we are eternally one."),
		category: VoiceCategory::Bond { level: 3 },
	},
	{
		path: "snd_voi_training_109701/snd_voi_training_109701_0009.m4a",
		translation: Some("My soul is yours. And your soul is mine."),
		category: VoiceCategory::Bond { level: 3 },
	},
}
