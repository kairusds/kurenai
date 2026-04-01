use serenity::{
	async_trait,
	builder::GetMessages,
	model::{
		channel::*,
		gateway::Ready,
		id::*,
		Timestamp
	},
	prelude::*
};
use std::{
	collections::HashSet,
	fs::{self, File},
	io::{BufRead, BufReader},
	sync::{Arc, Mutex, RwLock, atomic::{AtomicU64, Ordering}},
	process::Command,
	time::{Duration, SystemTime, UNIX_EPOCH}
};
use rand::{
	RngExt, SeedableRng, TryRng,
	distr::uniform::{SampleRange, SampleUniform},
	rngs::{ChaCha20Rng, SysRng}
};
use sha3::{Sha3_512, Digest};
use zeroize_derive::{Zeroize, ZeroizeOnDrop};
use tokio::time::{interval, MissedTickBehavior};
use chrono::{Datelike, /* Utc */Local};
// use chrono_tz::Asia::Tokyo;

const GACHA_IGNORE_USER_LIST: [u64; 1] = [757971702658498570];

static PULL_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct RoleGachaDrop {
	pub role_id: u64,
	pub label: &'static str,
}

#[derive(Clone)]
struct GachaTier {
	tier_name: &'static str,
	base_weight: u32,
	jitter: u32,
	drops: &'static [RoleGachaDrop]
}

const SSR_ROLE_DROPS: &[RoleGachaDrop] = &[
	RoleGachaDrop { role_id: 1488672805024436344, label: "SS+" },
	RoleGachaDrop { role_id: 1488672138121580675, label: "SS" },
	RoleGachaDrop { role_id: 1488672215024009298, label: "S+" },
	RoleGachaDrop { role_id: 1488673139427770398, label: "S" },
	RoleGachaDrop { role_id: 1488695883892523179, label: "A+" },
	RoleGachaDrop { role_id: 1488695909301620827, label: "A" },
];

const UR_ROLE_DROPS: &[RoleGachaDrop] = &[
	RoleGachaDrop { role_id: 1488672177937977435, label: "UF" },
	RoleGachaDrop { role_id: 1488672678440075354, label: "UG9" },
	RoleGachaDrop { role_id: 1488672713005596682, label: "UG" },
];

const SR_ROLE_DROPS: &[RoleGachaDrop] = &[
	RoleGachaDrop { role_id: 1488672903468941502, label: "B" },
	RoleGachaDrop { role_id: 1488672484411703396, label: "C" },
];

const R_ROLE_DROPS: &[RoleGachaDrop] = &[
	RoleGachaDrop { role_id: 1488672445358411848, label: "D" },
	RoleGachaDrop { role_id: 1488673341798613022, label: "E" },
	RoleGachaDrop { role_id: 1488672878130892920, label: "F" },
	RoleGachaDrop { role_id: 1488673384777912402, label: "G" },
];

const ROLE_GACHA_POOL: [GachaTier; 5] = [
	GachaTier { tier_name: "UR", base_weight: 5, jitter: 2, drops: UR_ROLE_DROPS },
	GachaTier { tier_name: "SSR", base_weight: 750, jitter: 150, drops: SSR_ROLE_DROPS },
	GachaTier { tier_name: "R", base_weight: 556, jitter: 80, drops: R_ROLE_DROPS },
	GachaTier { tier_name: "SR", base_weight: 191, jitter: 40, drops: SR_ROLE_DROPS },
	GachaTier { tier_name: "草", base_weight: 98498, jitter: 5000, drops: &[] },
];

#[derive(Zeroize, ZeroizeOnDrop)]
struct EntropyState {
	os_seed:[u8; 64],
	pq_hash_bytes: [u8; 64],
	chacha_seed: [u8; 32],
}

impl EntropyState {
	fn new() -> Self {
		Self { os_seed: [0u8; 64], pq_hash_bytes: [0u8; 64], chacha_seed: [0u8; 32] }
	}
}

pub fn perform_gacha_pull(user_id: u64, message_id: u64, content: &str) -> Option<(&'static str, RoleGachaDrop)> {
	let mut state = EntropyState::new();

	let sys_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
	let counter = PULL_COUNTER.fetch_add(1, Ordering::SeqCst);

	if SysRng.try_fill_bytes(&mut state.os_seed).is_err() {
		return None;
	}

	let mut hasher = Sha3_512::new();
	hasher.update(&state.os_seed);
	hasher.update(user_id.to_le_bytes());
	hasher.update(message_id.to_le_bytes());
	hasher.update((sys_time.subsec_nanos() as u64).to_le_bytes());
	hasher.update(sys_time.as_secs().to_le_bytes());
	hasher.update(counter.to_le_bytes());
	hasher.update(content.as_bytes());

	let pq_hash = hasher.finalize();
	state.pq_hash_bytes.copy_from_slice(&pq_hash);
	state.chacha_seed.copy_from_slice(&state.pq_hash_bytes[0..32]);

	let mut rng = ChaCha20Rng::from_seed(state.chacha_seed);

	let mut dynamic_pool: Vec<(GachaTier, u32)> = Vec::with_capacity(ROLE_GACHA_POOL.len());
	let mut total_weight: u32 = 0;

	for tier in ROLE_GACHA_POOL.iter() {
		let variance = rng.random_range(0..=(tier.jitter * 2));
		let mutated_weight = (tier.base_weight + variance).saturating_sub(tier.jitter);
		
		dynamic_pool.push((tier.clone(), mutated_weight));
		total_weight += mutated_weight;
	}

	let mut roll = rng.random_range(0..total_weight);
	let mut selected_tier = None;

	for (tier, weight) in dynamic_pool {
		if roll < weight {
			selected_tier = Some(tier);
			break;
		}
		roll -= weight;
	}

	if let Some(tier) = selected_tier {
		if tier.drops.is_empty() {
			return None;
		}

		let drop_index = rng.random_range(0..tier.drops.len());
		return Some((tier.tier_name, tier.drops[drop_index].clone()));
	}

	None
}

fn is_special_day() -> bool {
	let now = Local::now(); // Utc::now().with_timezone(&Tokyo);

	// mm/dd
	let special_days = [
		(1, 1), // new year
		(2, 14), // valentine's
		(3, 14), // white day (jp holiday)
		(4, 1), // april fools
		// golden week //
		(4, 29),
		(4, 30),
		(5, 1),
		(5, 2),
		(5, 3),
		(5, 4),
		(5, 5),
		(5, 6),
		//////////////////
		// obon //
		(8, 13),
		(8, 14),
		(8, 15),
		(8, 16),
		//////////
		(10, 31), // halloween
		(12, 25), // christmas
	];

	special_days.contains(&(now.month(), now.day()))
}

pub struct StoryLines {
	pub lines: RwLock<Vec<String>>
}

struct StoryLinesKey;

impl TypeMapKey for StoryLinesKey {
	type Value = Arc<StoryLines>;
}

impl StoryLines {
	pub fn load(&self, path: &str) {
		if let Ok(file) = File::open(path) {
			let reader = BufReader::new(file);
			let mut new_lines = Vec::new();

			for line in reader.lines().filter_map(Result::ok) {
				let trimmed = line.trim();
				if !trimmed.is_empty() {
					new_lines.push(trimmed.to_string());
				}
			}

			new_lines.shrink_to_fit();

			let mut write_lock = self.lines.write().unwrap();
			*write_lock = new_lines;
			println!("Story lines loaded. Total length: {}", write_lock.len());
		} else {
			eprintln!("Failed to open {} - make sure it exists!", path);
		}
	}

	pub fn get_random(&self) -> Option<String> {
		let lock = self.lines.read().unwrap();
		if lock.is_empty() {
			return None;
		}
		let index: usize = rng_range(0..lock.len());
		Some(lock[index].clone())
	}
}


pub struct PhishingProtect {
	pub set: RwLock<HashSet<String>>
}

struct PhishingKey;

impl TypeMapKey for PhishingKey {
	type Value = Arc<PhishingProtect>;
}

impl PhishingProtect {
	pub fn load(&self, path: &str) {
		if let Ok(file) = File::open(path) {
			let reader = BufReader::new(file);
			let mut new_set = HashSet::new();

			for line in reader.lines().filter_map(Result::ok) {
				let trimmed = line.trim();
				if !trimmed.is_empty() {
					new_set.insert(trimmed.to_lowercase());
				}
			}

			new_set.shrink_to_fit();

			let mut write_lock = self.set.write().unwrap();
			*write_lock = new_set;
			println!("Phishing list updated. Total length: {}", write_lock.len());
		}
	}
}

struct StickyState {
	enabled: bool,
	last_sticky_id: Mutex<Option<MessageId>>,
	last_author_id: Mutex<Option<UserId>>
}

struct StickyKey;
impl TypeMapKey for StickyKey {
	type Value = Arc<StickyState>;
}

const HELP_CHANNEL_ID: u64 = 1248143441242619955;
const STICKY_MESSAGE: &str = r#"# :warning: BEFORE ASKING A QUESTION :warning:
- Having runtime errors? Install [Hachimi Edge](https://hachimi.noccu.art).
- Check for your issue in [Troubleshooting](https://hachimi.noccu.art/docs/hachimi/troubleshooting) or the [FAQ](https://hachimi.noccu.art/docs/hachimi/faqs).
- Check the pins and backread messsages in this channel.

You will be intentionally ignored if the sources mentioned above cover your issue.
Still can't find the solution for your problem? Ping the `@Helpdesk` role.
Bugs instead of tech issue? Check <#1248143380437930085>."#;

async fn start_sticky_worker(ctx: Context, state: Arc<StickyState>) {
	let mut interval = interval(Duration::from_secs(10));
	let channel_id = ChannelId::new(HELP_CHANNEL_ID);

	loop {
		interval.tick().await;

		let messages = match channel_id.messages(&ctx.http, GetMessages::new().limit(1)).await {
			Ok(msgs) => msgs,
			Err(e) => {
				eprintln!("Failed to fetch last message: {}", e);
				continue;
			}
		};

		if let Some(last_msg) = messages.first() {
			let now = Timestamp::now();
			let last_msg_time = last_msg.timestamp;

			let duration_since_last_msg = now.unix_timestamp() - last_msg_time.unix_timestamp();

			let mut should_delete_id = None;
			let mut should_post = false;

			{
				let mut id_lock = state.last_sticky_id.lock().unwrap();
				if duration_since_last_msg >= 120 {
					if id_lock.map_or(true, |id| id != last_msg.id) {
						should_delete_id = id_lock.take();
						should_post = true;
					}
				}
			}

			if let Some(id) = should_delete_id {
				let _ = channel_id.delete_message(&ctx.http, id).await;
			}

			if should_post {
				if let Ok(new_msg) = channel_id.say(&ctx.http, STICKY_MESSAGE).await {
					let mut id_lock = state.last_sticky_id.lock().unwrap();
					*id_lock = Some(new_msg.id);
				}
			}
		}
	}
}

struct Handler;

fn should_show(rate: f64) -> bool {
	rand::rng().random_bool(rate)
}

fn rng_range<T, R>(range: R) -> T where T: SampleUniform, R: SampleRange<T> {
	rand::rng().random_range(range)
}

#[async_trait]
impl EventHandler for Handler {
	async fn message(&self, ctx: Context, msg: Message) {
		let target_guild_id = 1248085334861025350; // hachimi project official server

		if msg.author.bot || msg.guild_id.map_or(true, |id| id.get() != target_guild_id) {
			return;
		}

		let data = ctx.data.read().await;
		let protect = data.get::<PhishingKey>().cloned().expect("PhishingProtect missing");
		let sticky = data.get::<StickyKey>().cloned().expect("StickyState missing");
		drop(data);

		let is_phishing = {
			let bad_links = protect.set.read().unwrap();
			msg.content.split_whitespace().any(|word| {
				bad_links.contains(&word.to_lowercase())
			})
		};

		if is_phishing {
			if let Err(e) = msg.delete(&ctx.http).await {
				eprintln!("Failed to delete phishing message: {}", e);
			} else {
				let emojis = [
					"<:unai2:1463880445669281876>",
					"<:unai3:1463880567400566825>"
				];
				let index: usize = rng_range(0..emojis.len());
				let emoji = emojis[index];
				let response = format!("{} bad link! {}", msg.author.mention(), emoji);
				let _ = msg.channel_id.say(&ctx.http, response).await;
			}
			return;
		}		

		if msg.channel_id.get() == HELP_CHANNEL_ID {
			let mut should_delete_id = None;
			{
				let mut last_author = sticky.last_author_id.lock().unwrap();
				let mut id_lock = sticky.last_sticky_id.lock().unwrap();

				if let Some(previous_author_id) = *last_author {
					if previous_author_id != msg.author.id {
						should_delete_id = id_lock.take();
					}
				}

				*last_author = Some(msg.author.id);
			}

			if let Some(id) = should_delete_id {
				let _ = msg.channel_id.delete_message(&ctx.http, id).await;
			}
		}

		// let content_lower = msg.content.to_lowercase();
		// 0.01% on help channel, 0.1% on all channels
		let rate = if msg.channel_id.get() == HELP_CHANNEL_ID { 0.0001 } else { 0.001 };
		if should_show(rate) {
			let silly_emojis = [
				"<a:sildance:1462056515056828499>",
				"<:sillier:1463878217197682865>",
				"<a:Sillymambo:1463878469610897485>",
				"<:stillinstare:1463878652402860228>"
			];
			
			let index: usize = rng_range(0..silly_emojis.len());
			let emoji = silly_emojis[index];
			let _ = msg.reply(&ctx.http, emoji).await;
			if let Ok(reaction) = ReactionType::try_from(emoji) {
				let _ = msg.react(&ctx.http, reaction).await;
			}
		}

		// 0.01% on help channel, 0.5% on all channels
		let msg_rate = if msg.channel_id.get() == HELP_CHANNEL_ID { 0.0001 } else { 0.005 };
		if should_show(msg_rate) {
			let data = ctx.data.read().await;
			let stories = data.get::<StoryLinesKey>().cloned().expect("StoryLines missing");
			drop(data);

			if let Some(random_quote) = stories.get_random() {
				let _ = msg.reply(&ctx.http, random_quote).await;
			}
		}

		if is_special_day() && !GACHA_IGNORE_USER_LIST.contains(&msg.author.id.get()) {
			if let Some((tier_name, outcome)) = perform_gacha_pull(msg.author.id.get(), msg.id.get(), &msg.content) {
				let role_id_raw = outcome.role_id;
				let role_id = RoleId::new(role_id_raw);
				let guild_id = msg.guild_id.expect("Only works in servers");
	
				let has_role = msg.member.as_ref()
					.map_or(false, |m| m.roles.contains(&role_id));
	
				if !has_role {
					if let Ok(_) = ctx.http.add_member_role(guild_id, msg.author.id, role_id, Some("Role gacha from Silly bot")).await {
						if tier_name == "UR" {
							let ur_messages = [
								"...Ah. My love... you obtained [UR] {}. As expected of mY destined pErson... Ahh, seeing you so blessed makes my heart buzz... I want to take all of this joy, and... slurp it up... Fufu...",
								"...Ah! T-Trainer-san... You got [UR] {}! I am... so incredibly glad that such wonderful fortune has found you. To think I am allowed to share this special moment right by your side... Is it really okay... for me to receive this much happiness...?"
							];
							
							let index: usize = rng_range(0..ur_messages.len());
							let response = ur_messages[index].replace("{}", outcome.label);
							let _ = msg.reply(&ctx.http, response).await;
						} else if tier_name == "SSR" {
							let ssr_messages = [
								"...Congratulations, Trainer-san. You managed to welcome [SSR] {}. Seeing your joyful expression makes me... so very happy, too. ...Please, let me stay by your side and watch you... mooore...",
								"...Ah... fufu. I'm so happy you got [SSR] {}, my Trainer-san. Seeing how delighted you are... it makes me feel like I am submerged in warm water. ...I hope I can always be here... to share these gentle feelings with you..."
							];
							
							let index: usize = rng_range(0..ssr_messages.len());
							let response = ssr_messages[index].replace("{}", outcome.label);
							let _ = msg.reply(&ctx.http, response).await;
						} else if tier_name == "SR" {
							let _ = msg.reply(&ctx.http, format!("...My, you got [SR] {}. That is wonderful, isn't it. ...Fufu, whether the result is grand or modest, as long as I can share this time with you... I feel like I can be alright.", outcome.label)).await;
						} else if tier_name == "R" {
							let _ = msg.reply(&ctx.http, format!("...You received [R] {}. Please do not be discouraged... Even if fortune did not favor you this time... I am right here. I will accept everything about you, so... please, let me comfort you...", outcome.label)).await;
						}
					}
				}
			}
		}
	}

	async fn ready(&self, ctx: Context, ready: Ready) {
		println!("{} is connected!", ready.user.name);
		let data = ctx.data.read().await;
		let sticky_state = data.get::<StickyKey>().cloned().expect("StickyKey missing");

		if sticky_state.enabled {
			let ctx_clone = ctx.clone();
			tokio::spawn(async move {
				start_sticky_worker(ctx_clone, sticky_state).await;
			});
		}
	}
}

async fn start_daily_download(url: String, filename: String, protect: Arc<PhishingProtect>) {
	let mut timer = interval(Duration::from_secs(86400));
	timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

	loop {
		timer.tick().await;
		println!("Downloading {}...", url);

		let tmp_filename = format!("{}.tmp", filename);
		let status = Command::new("curl")
			.arg("-L")
			.arg("-o")
			.arg(&tmp_filename)
			.arg(&url)
			.status();

		match status {
			Ok(s) if s.success() => {
				if let Err(e) = fs::rename(&tmp_filename, &filename) {
					eprintln!("Daily update failed: {}", e);
				} else {
					protect.load(&filename);
					println!("Successfully downloaded: {}", filename);
				}
			}
			Ok(s) => eprintln!("Curl exited with error: {}", s),
			Err(e) => eprintln!("Failed to execute curl: {}", e),
		}
	}
}

#[tokio::main]
async fn main() {
	dotenvy::dotenv().ok();

	let protect = Arc::new(PhishingProtect {
		set: RwLock::new(HashSet::new())
	});
	protect.load("phishing.txt");

	let story_lines = Arc::new(StoryLines {
		lines: RwLock::new(Vec::new())
	});
	story_lines.load("chara_story_lines.txt");

	let sticky_state = Arc::new(StickyState {
		enabled: false,
		last_sticky_id: Mutex::new(None),
		last_author_id: Mutex::new(None)
	});

	let protect_clone = Arc::clone(&protect);
	tokio::spawn(async move {
		start_daily_download(
			// big thanks to https://github.com/Phishing-Database/Phishing.Database
			"https://phish.co.za/latest/phishing-links-ACTIVE.txt".to_string(), 
			"phishing.txt".to_string(),
			protect_clone
		).await;
	});

	let token = std::env::var("TOKEN").expect("Expected a token in the environment");
	let intents = GatewayIntents::GUILD_MESSAGES
		| GatewayIntents::MESSAGE_CONTENT
		| GatewayIntents::GUILD_MEMBERS;

	let mut client = Client::builder(&token, intents)
		.event_handler(Handler)
		.await
		.expect("Err creating client");

	{
		let mut data = client.data.write().await;
		data.insert::<PhishingKey>(protect);
		data.insert::<StickyKey>(sticky_state);
		data.insert::<StoryLinesKey>(story_lines);
	}

	if let Err(why) = client.start().await {
		println!("Client error: {:?}", why);
	}
}
