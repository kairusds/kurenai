use serenity::{
	async_trait,
	builder::{CreateEmbed, CreateMessage, EditChannel, GetMessages},
	http::Http,
	model::{
		channel::*,
		gateway::Ready,
		id::*,
		Timestamp,
		user::PremiumType
	},
	prelude::*
};
use std::{
	collections::{HashMap, HashSet, VecDeque},
	fs::{self, File},
	io::{BufRead, BufReader},
	sync::{Arc, Mutex, RwLock, atomic::{AtomicU64, Ordering}},
	process::Command,
	time::{Duration, Instant, SystemTime, UNIX_EPOCH}
};
use rand::{
	RngExt, SeedableRng, TryRng,
	distr::uniform::{SampleRange, SampleUniform},
	rngs::{ChaCha20Rng, SysRng}
};
use sha3::{Sha3_512, Digest};
use zeroize_derive::{Zeroize, ZeroizeOnDrop};
use tokio::time::{interval, sleep, MissedTickBehavior};
use chrono::{Datelike, Utc};
use chrono_tz::Asia::Tokyo;

const GACHA_IGNORE_USER_LIST: [u64; 1] = [757971702658498570];

static PULL_COUNTER: AtomicU64 = AtomicU64::new(0);

const SILLY_CHANNEL: u64 = 1489631089919000636;

const TRAP_CHANNEL_ID: u64 = 1514678047066951761;

const EVIDENCE_LOG_CHANNEL_ID: u64 = 1514679589534961794;

const DELETE_DELAY_MS: u64 = 1500;
const BULK_DELETE_DELAY_MS: u64 = 2000;
const FETCH_DELAY_MS: u64 = 1100;
const MAX_FETCH_PAGES_PER_CHANNEL: usize = 10;

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

const UR_SPECIAL_DROPS: &[SpecialGachaDrop] = &[
	SpecialGachaDrop { prize: "basic_nitro", message: "Yes... but I am not afraid. As long as I am with you, no matter what path it may be...
...--Therefore, please do not fear, either.
...Someday, will you expose... more of yourself to me?
<@757971702658498570>" },
];

const SPECIAL_GACHA_POOL: [GachaTier<SpecialGachaDrop>; 5] =[
	GachaTier { tier_name: "UR", base_weight: 5, jitter: 2, drops: UR_SPECIAL_DROPS },
	GachaTier { tier_name: "SSR", base_weight: 750, jitter: 150, drops: &[] },
	GachaTier { tier_name: "R", base_weight: 556, jitter: 80, drops: &[] },
	GachaTier { tier_name: "SR", base_weight: 191, jitter: 40, drops: &[] },
	GachaTier { tier_name: "草", base_weight: 98498, jitter: 5000, drops: &[] },
];

pub struct GachaTier<T: 'static> {
	pub tier_name: &'static str,
	pub base_weight: u32,
	pub jitter: u32,
	pub drops: &'static [T]
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

const ROLE_GACHA_POOL: [GachaTier<RoleGachaDrop>; 5] =[
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

pub fn perform_gacha_pull<T: Clone + 'static>(
	user_id: u64,
	message_id: u64,
	content: &str,
	pool: &[GachaTier<T>]
) -> Option<(&'static str, T)> {
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

	let mut dynamic_pool: Vec<(&GachaTier<T>, u32)> = Vec::with_capacity(pool.len());
	let mut total_weight: u32 = 0;

	for tier in pool.iter() {
		let variance = rng.random_range(0..=(tier.jitter * 2));
		let mutated_weight = (tier.base_weight + variance).saturating_sub(tier.jitter);

		dynamic_pool.push((tier, mutated_weight));
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
	let now = Utc::now().with_timezone(&Tokyo);

	// mm/dd
	let special_days = [
		(1, 1), // new year
		(2, 14), // valentine's
		(2, 24), // uma jp anniversary
		(3, 14), // white day (jp holiday)
		(3, 29), // hachimi's first release (https://github.com/Hachimi-Hachimi/Hachimi/releases/tag/v0.1.0)
		(4, 1), // april fools
		(4, 5), // easter
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
		// june bride //
		(6, 7),
		(6, 8),
		(6, 9),
		(6, 10),
		(6, 11),
		(6, 12),
		(6, 13),
		///////////////
		(7, 7), // tanabata
		(7, 20), // marine day
		// obon //
		(8, 13),
		(8, 14),
		(8, 15),
		(8, 16),
		////////
		(8, 24), // uma jp half anniversary
		(8, 25), // otsukimi
		(10, 12), // sports day
		(10, 31), // halloween
		(11, 23), // labor thanksgiving day
		(12, 24), // christmas eve
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

pub struct UserSillyReplyState {
	pub queue: VecDeque<Message>,
	pub current_delay: Duration,
	pub next_allowed_time: Instant,
}

pub struct SillyReplyQueue {
	pub users: Mutex<HashMap<u64, UserSillyReplyState>>,
}

struct SillyReplyQueueKey;

impl TypeMapKey for SillyReplyQueueKey {
	type Value = Arc<SillyReplyQueue>;
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

async fn start_story_worker(ctx: Context, state: Arc<SillyReplyQueue>) {
	let mut interval = interval(Duration::from_millis(500)); // tick frequently to check all users
	loop {
		interval.tick().await;

		let mut msg_to_send = None;

		{
			let mut users = state.users.lock().unwrap();
			let now = Instant::now();

			for (_, user_state) in users.iter_mut() {
				// find the first user who has a message ready and has passed their timeout
				if !user_state.queue.is_empty() && now >= user_state.next_allowed_time {
					msg_to_send = user_state.queue.pop_front();

					// increase the delay for their NEXT message to punish spam
					// adds 2 seconds each time, capped at 30 seconds maximum wait
					user_state.current_delay = (user_state.current_delay + Duration::from_secs(2))
						.min(Duration::from_secs(30));

					user_state.next_allowed_time = now + user_state.current_delay;
					break; // only process one message across all users per global tick to prevent API rate limits
				}
			}
		}

		if let Some(msg) = msg_to_send {
			let data = ctx.data.read().await;
			let stories = data.get::<StoryLinesKey>().cloned().expect("StoryLines missing");
			drop(data);

			if let Some(random_quote) = stories.get_random() {
				let _ = msg.reply(&ctx.http, random_quote).await;
			}
		}
	}
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

pub struct OwnersList {
	pub ids: RwLock<HashSet<u64>>,
}

struct OwnersKey;

impl TypeMapKey for OwnersKey {
	type Value = Arc<OwnersList>;
}

impl OwnersList {
	pub fn load(&self, path: &str) {
		if let Ok(file) = File::open(path) {
			let reader = BufReader::new(file);
			let mut new_ids = HashSet::new();

			for line in reader.lines().filter_map(Result::ok) {
				let trimmed = line.trim();
				if !trimmed.is_empty() {
					if let Ok(id) = trimmed.parse::<u64>() {
						new_ids.insert(id);
					} else {
						eprintln!("Invalid user ID in {}: '{}'", path, trimmed);
					}
				}
			}

			new_ids.shrink_to_fit();

			let mut write_lock = self.ids.write().unwrap();
			*write_lock = new_ids;
			println!("Owners loaded. Total count: {}", write_lock.len());
		} else {
			eprintln!("Failed to open {} — owners file not found! No users will be whitelisted from the trap channel.", path);
		}
	}

	pub fn contains(&self, id: u64) -> bool {
		let lock = self.ids.read().unwrap();
		lock.contains(&id)
	}
}

pub struct SafeWordsList {
	pub words: RwLock<Vec<String>>,
}

struct SafeWordsKey;

impl TypeMapKey for SafeWordsKey {
	type Value = Arc<SafeWordsList>;
}

impl SafeWordsList {
	pub fn load(&self, path: &str) {
		if let Ok(file) = File::open(path) {
			let reader = BufReader::new(file);
			let mut new_words = Vec::new();

			for line in reader.lines().filter_map(Result::ok) {
				let trimmed = line.trim();
				if !trimmed.is_empty() && !trimmed.starts_with('#') {
					new_words.push(trimmed.to_string());
				}
			}

			new_words.shrink_to_fit();

			let mut write_lock = self.words.write().unwrap();
			*write_lock = new_words;
			println!("Safe words loaded. Total length: {}", write_lock.len());
		} else {
			eprintln!("Failed to open {}, safe-words file not found!", path);
		}
	}

	pub fn get_random(&self) -> Option<String> {
		let lock = self.words.read().unwrap();
		if lock.is_empty() {
			return None;
		}
		let index: usize = rng_range(0..lock.len());
		Some(lock[index].clone())
	}
}

struct BanTracker {
	pending: Mutex<HashSet<u64>>,
}

struct BanTrackerKey;

impl TypeMapKey for BanTrackerKey {
	type Value = Arc<BanTracker>;
}

fn channel_has_messages(kind: ChannelType) -> bool {
	matches!(
		kind,
		ChannelType::Text
		| ChannelType::PublicThread
		| ChannelType::PrivateThread
	)
}

async fn handle_trap_message(ctx: &Context, msg: &Message) {
	{
		let data = ctx.data.read().await;
		let owners = data.get::<OwnersKey>().expect("OwnersKey missing");
		if owners.contains(msg.author.id.get()) {
			return;
		}
	}

	if msg.webhook_id.is_some() {
		let webhook_id = msg.webhook_id.unwrap();
		eprintln!(
			"Webhook message detected in trap channel from webhook {}. Deleting message & webhook.",
			webhook_id
		);

		let _ = send_webhook_evidence(&ctx.http, msg).await;

		let _ = msg.delete(&ctx.http).await;

		if let Err(e) = ctx.http.delete_webhook(webhook_id, None).await {
			eprintln!("Failed to delete webhook {}: {}", webhook_id, e);
		}

		rename_trap_channel(ctx).await;
		return;
	}

	{
		let should_skip = {
			let tracker = {
				let data = ctx.data.read().await;
				data.get::<BanTrackerKey>().cloned().expect("BanTracker missing")
			};
			let mut pending = tracker.pending.lock().unwrap();
			if pending.contains(&msg.author.id.get()) {
				true
			} else {
				pending.insert(msg.author.id.get());
				false
			}
		};
		if should_skip {
			let _ = msg.delete(&ctx.http).await;
			return;
		}
	}

	let guild_id = match msg.guild_id {
		Some(id) => id,
		None => {
			remove_pending(ctx, msg.author.id).await;
			return;
		}
	};

	let user_id = msg.author.id;
	let user_name = msg.author.name.clone();
	let user_display = msg.author.global_name.clone().unwrap_or_else(|| user_name.clone());
	let avatar_url = msg.author.avatar_url().unwrap_or_default();
	let content = msg.content.clone();
	let msg_timestamp = msg.timestamp;
	let attachments = msg.attachments.clone();
	let is_bot_user = msg.author.bot;

	send_evidence_embed(&ctx.http, &user_name, &user_display, user_id, &avatar_url, &content, msg_timestamp, &attachments).await;

	let deleted_count = delete_all_user_messages(ctx, guild_id, user_id).await;
	println!("Purged {} message(s) from scammer {} ({})", deleted_count, user_name, user_id);

	if is_bot_user {
		eprintln!("Note: user {} is a bot account — attempting ban anyway.", user_id);
	}

	match guild_id.ban_with_reason(&ctx.http, user_id, 7, "Auto-banned: scam bot detected in trap channel").await {
		Ok(()) => println!("Banned scam bot: {} ({})", user_name, user_id),
		Err(e) => {
			eprintln!("Failed to ban user {} ({}): {}", user_name, user_id, e);
		}
	}

	rename_trap_channel(ctx).await;
	remove_pending(ctx, user_id).await;
}

async fn remove_pending(ctx: &Context, user_id: UserId) {
	let data = ctx.data.read().await;
	let tracker = data.get::<BanTrackerKey>().expect("BanTracker missing");
	let mut pending = tracker.pending.lock().unwrap();
	pending.remove(&user_id.get());
}

async fn send_evidence_embed(
	http:&Http,
	name: &str,
	display: &str,
	uid: UserId,
	avatar: &str,
	content: &str,
	ts: Timestamp,
	attachs: &[Attachment],
) {
	let log_ch = ChannelId::new(EVIDENCE_LOG_CHANNEL_ID);

	let mut embed = CreateEmbed::new()
		.title("\u{1F6A8} Scam Bot Detected")
		.color(0xFF0000)
		.thumbnail(avatar)
		.field("Username", name.to_string(), true)
		.field("Display Name", display.to_string(), true)
		.field("User ID", uid.to_string(), true)
		.field("Message Content",
			if content.is_empty() { "*No text content, likely image-only scam*".to_string() } else { content.to_string() },
			false
		)
		.field("Sent At", ts.to_string(), true);

	if !attachs.is_empty() {
		let list: Vec<String> = attachs.iter()
			.map(|a| format!("{} ({} bytes) - {}", a.filename, a.size, a.url))
			.collect();
		embed = embed.field("Attachments", list.join("\n"), false);
	}

	embed = embed
		.field("Action Taken", "All messages purged + User banned indefinitely", false)
		.timestamp(Timestamp::now());

	if let Err(e) = log_ch.send_message(http, CreateMessage::new().add_embed(embed)).await {
		eprintln!("Failed to send evidence embed: {}", e);
	}
}

async fn send_webhook_evidence(http: &Http, msg: &Message) -> Result<Message, SerenityError> {
	let log_ch = ChannelId::new(EVIDENCE_LOG_CHANNEL_ID);
	let wid = msg.webhook_id.map_or("unknown".to_string(), |id| id.to_string());

	let embed = CreateEmbed::new()
		.title("\u{1F6A8} Webhook Scam Detected")
		.color(0xFFAA00)
		.field("Webhook ID", wid, true)
		.field("Author", msg.author.name.clone(), true)
		.field("Content",
			if msg.content.is_empty() { "*No text*".to_string() } else { msg.content.clone() },
			false)
		.field("Action Taken", "Message deleted + Webhook deleted (if possible)", false)
		.timestamp(Timestamp::now());

	log_ch.send_message(http, CreateMessage::new().add_embed(embed)).await
}

async fn delete_all_user_messages(ctx: &Context, guild_id: GuildId, user_id: UserId) -> u64 {
	let channels = match guild_id.channels(&ctx.http).await {
		Ok(ch) => ch,
		Err(e) => {
			eprintln!("Failed to get guild channels: {}", e);
			return 0;
		}
	};

	let mut total_deleted: u64 = 0;

	for (channel_id, channel) in &channels {
		if !channel_has_messages(channel.kind) {
			continue;
		}
		total_deleted += delete_user_messages_in_channel(&ctx.http, *channel_id, user_id).await;
	}

	if let Ok(threads_resp) = guild_id.get_active_threads(&ctx.http).await {
		for thread in &threads_resp.threads {
			total_deleted += delete_user_messages_in_channel(&ctx.http, thread.id, user_id).await;
		}
	}

	total_deleted
}

async fn delete_user_messages_in_channel(http: &Http, channel_id: ChannelId, user_id: UserId) -> u64 {
	let mut deleted: u64 = 0;
	let mut recent_ids: Vec<MessageId> = Vec::new();
	let mut old_ids: Vec<MessageId> = Vec::new();

	let fourteen_days_ago = Timestamp::now().unix_timestamp() - (14 * 24 * 3600);

	let mut cursor: Option<MessageId> = None;

	for _ in 0..MAX_FETCH_PAGES_PER_CHANNEL {
		let mut builder = GetMessages::new().limit(100);
		if let Some(id) = cursor {
			builder = builder.before(id);
		}

		let batch = match channel_id.messages(http, builder).await {
			Ok(msgs) => msgs,
			Err(e) => {
				if !e.to_string().contains("50001") && !e.to_string().contains("50013") {
					eprintln!("Failed to fetch messages from channel {}: {}", channel_id, e);
				}
				break;
			}
		};

		if batch.is_empty() {
			break;
		}

		cursor = batch.last().map(|m| m.id);

		for msg in &batch {
			if msg.author.id == user_id {
				if msg.timestamp.unix_timestamp() >= fourteen_days_ago {
					recent_ids.push(msg.id);
				} else {
					old_ids.push(msg.id);
				}
			}
		}

		let oldest_ts = batch.last().map(|m| m.timestamp.unix_timestamp()).unwrap_or(i64::MAX);
		if oldest_ts < fourteen_days_ago && recent_ids.is_empty() && old_ids.is_empty() {
			break;
		}

		sleep(Duration::from_millis(FETCH_DELAY_MS)).await;
	}

	while recent_ids.len() >= 2 {
		let end = std::cmp::min(100, recent_ids.len());
		let batch: Vec<MessageId> = recent_ids.drain(..end).collect();

		match channel_id.delete_messages(http, &batch).await {
			Ok(()) => deleted += batch.len() as u64,
			Err(e) => {
				eprintln!(
					"Bulk delete failed in channel {} ({} messages): {}. Falling back to individual deletes.",
					channel_id, batch.len(), e
				);
				for id in &batch {
					if channel_id.delete_message(http, *id).await.is_ok() {
						deleted += 1;
					}
					sleep(Duration::from_millis(DELETE_DELAY_MS)).await;
				}
			}
		}

		sleep(Duration::from_millis(BULK_DELETE_DELAY_MS)).await;
	}

	for id in recent_ids.into_iter().chain(old_ids.into_iter()) {
		match channel_id.delete_message(http, id).await {
			Ok(()) => deleted += 1,
			Err(e) => {
				let err_str = e.to_string();
				if !err_str.contains("10008") {
					eprintln!("Failed to delete message {} in {}: {}", id, channel_id, e);
				}
			}
		}
		sleep(Duration::from_millis(DELETE_DELAY_MS)).await;
	}

	deleted
}

async fn rename_trap_channel(ctx: &Context) {
	let safe_words = {
		let data = ctx.data.read().await;
		data.get::<SafeWordsKey>().cloned().expect("SafeWordsKey missing")
	};

	let new_name = match safe_words.get_random() {
		Some(w) => w,
		None => {
			eprintln!("Safe words list is empty, skipping trap channel rename");
			return;
		}
	};

	let channel_id = ChannelId::new(TRAP_CHANNEL_ID);

	match channel_id.edit(&ctx.http, EditChannel::new().name(&new_name)).await {
		Ok(_) => println!("Renamed trap channel to \"{}\"", new_name),
		Err(e) => eprintln!("Failed to rename trap channel: {}", e),
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

		if msg.channel_id.get() == TRAP_CHANNEL_ID {
			let ctx_clone = ctx.clone();
			let msg_clone = msg.clone();
			tokio::spawn(async move {
				handle_trap_message(&ctx_clone, &msg_clone).await;
			});
			return;
		}

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

		if msg.channel_id.get() == SILLY_CHANNEL {
			let data = ctx.data.read().await;
			let queue_state = data.get::<SillyReplyQueueKey>().cloned().expect("SillyReplyQueue missing");
			drop(data);

			let mut users = queue_state.users.lock().unwrap();
			let state = users.entry(msg.author.id.get()).or_insert_with(|| UserSillyReplyState {
				queue: VecDeque::new(),
				current_delay: Duration::from_secs(2),
				next_allowed_time: Instant::now(),
			});

			// if the user's queue is empty, check if they've been idle to reset their delays
			if state.queue.is_empty() {
				let now = Instant::now();
				if now > state.next_allowed_time {
					// if they haven't sent a message in over 10s past their last timeout, fully reset their delay
					if now.duration_since(state.next_allowed_time) > Duration::from_secs(10) {
						state.current_delay = Duration::from_secs(2);
					}
					// apply their current delay starting from NOW
					state.next_allowed_time = now + state.current_delay;
				}
			}

			// hard-capped at 10,000 to prevent malicious out-of-memory attacks
			if state.queue.len() < 10_000 {
				state.queue.push_back(msg.clone());
			}
		}

		if is_special_day() && !GACHA_IGNORE_USER_LIST.contains(&msg.author.id.get()) {
			if let Some((tier_name, outcome)) = perform_gacha_pull(msg.author.id.get(), msg.id.get(), &msg.content, &ROLE_GACHA_POOL) {
				let role_id_raw = outcome.role_id;
				let role_id = RoleId::new(role_id_raw);
				let guild_id = msg.guild_id.unwrap();

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

		if let Some((_tier, outcome)) = perform_gacha_pull(msg.author.id.get(), msg.id.get(), &msg.content, &SPECIAL_GACHA_POOL) {
			let prize = outcome.prize;

			if prize == "basic_nitro" && msg.author.premium_type == PremiumType::None {
				let winner_file = "nitro_claimed.txt";

				if std::path::Path::new(winner_file).exists() {
					return;
				}

				if let Ok(bot_reply) = msg.reply(&ctx.http, outcome.message).await {
					let winner_msg_link = msg.link();
					let bot_reply_link = bot_reply.link();

					let log_entry = format!(
						"Winner: {} ({})\nTime: {}\nWinner Message: {}\nBot Reply: {}\n-------------------\n",
						msg.author.name,
						msg.author.id,
						Timestamp::now(),
						winner_msg_link,
						bot_reply_link
					);

					if let Err(e) = fs::write(winner_file, log_entry) {
						eprintln!("Failed to save nitro winner log: {}", e);
					}
				}
			}
		}
	}

	async fn ready(&self, ctx: Context, ready: Ready) {
		println!("{} is connected!", ready.user.name);
		let data = ctx.data.read().await;
		let sticky_state = data.get::<StickyKey>().cloned().expect("StickyKey missing");
		let story_queue = data.get::<SillyReplyQueueKey>().cloned().expect("SillyReplyQueue missing");

		if sticky_state.enabled {
			let ctx_clone = ctx.clone();
			tokio::spawn(async move {
				start_sticky_worker(ctx_clone, sticky_state).await;
			});
		}

		let ctx_clone2 = ctx.clone();
		tokio::spawn(async move {
			start_story_worker(ctx_clone2, story_queue).await;
		});
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

	let story_queue = Arc::new(SillyReplyQueue {
		users: Mutex::new(HashMap::new())
	});

	let sticky_state = Arc::new(StickyState {
		enabled: false,
		last_sticky_id: Mutex::new(None),
		last_author_id: Mutex::new(None)
	});

	let safe_words = Arc::new(SafeWordsList {
		words: RwLock::new(Vec::new())
	});
	safe_words.load("safe_english_words.txt");

	let owners = Arc::new(OwnersList {
		ids: RwLock::new(HashSet::new())
	});
	owners.load("owners.txt");

	let ban_tracker = Arc::new(BanTracker {
		pending: Mutex::new(HashSet::new())
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
		data.insert::<SillyReplyQueueKey>(story_queue);
		data.insert::<SafeWordsKey>(safe_words);
		data.insert::<OwnersKey>(owners);
		data.insert::<BanTrackerKey>(ban_tracker);
	}

	if let Err(why) = client.start().await {
		println!("Client error: {:?}", why);
	}
}
