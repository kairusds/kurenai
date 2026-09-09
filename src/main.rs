use serenity::{
	async_trait,
	builder::{
		CreateActionRow, CreateAttachment, CreateButton, CreateCommand, CreateEmbed,
		CreateEmbedAuthor, CreateEmbedFooter, CreateInputText, CreateInteractionResponse,
		CreateInteractionResponseMessage, CreateMessage, CreateModal, CreateSelectMenu,
		CreateSelectMenuKind, CreateSelectMenuOption, EditChannel, EditInteractionResponse,
		GetMessages
	},
	http::Http,
	model::{
		application::{
			ActionRowComponent, ButtonStyle, CommandInteraction,
			ComponentInteraction, ComponentInteractionDataKind, CommandType,
			InputTextStyle, Interaction, ModalInteraction
		},
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
	io::{BufRead, BufReader, Cursor},
	sync::{Arc, Mutex, RwLock, atomic::{AtomicU64, Ordering}},
	process::Command,
	time::{Duration, Instant, SystemTime, UNIX_EPOCH}
};
use image::{ExtendedColorType, ImageFormat, ImageReader, codecs::webp::WebPEncoder};
use tokio::time::{interval, timeout, MissedTickBehavior};
use rand::{
	RngExt, SeedableRng, TryRng,
	distr::uniform::{SampleRange, SampleUniform},
	rngs::{ChaCha20Rng, SysRng}
};
use sha3::{Sha3_512, Digest};
use zeroize_derive::{Zeroize, ZeroizeOnDrop};
use chrono::{Datelike, Utc};
use chrono_tz::Asia::Tokyo;

mod consts;
use consts::*;

static PULL_COUNTER: AtomicU64 = AtomicU64::new(0);

fn parse_env<T>(key: &str) -> T where
	T: std::str::FromStr,
	T::Err: std::fmt::Display {
	let val = std::env::var(key).unwrap_or_else(|_| panic!("Missing environment variable: {key}"));
	val.parse().unwrap_or_else(|e| panic!("Failed to parse {key} ({val:?}): {e}"))
}

fn parse_env_list<T>(key: &str) -> Vec<T> where
	T: std::str::FromStr,
	T::Err: std::fmt::Display {
	let val = std::env::var(key).unwrap_or_else(|_| panic!("Missing environment variable: {key}"));
	val.split(',')
		.map(|s| s.trim())
		.filter(|s| !s.is_empty())
		.map(|s| s.parse().unwrap_or_else(|e| panic!("Failed to parse item in {key} ({s:?}): {e}")))
		.collect()
}

pub struct BotConfig {
	pub target_guild_id: u64,
	pub trap_channel_id: u64,
	pub evidence_log_channel_id: u64,
	pub silly_channel_id: u64,
	pub help_channel_id: u64,
	pub gacha_ignore_user_id: u64,
	pub appeal_url: String,
	pub sticky_enabled: bool,
	pub owner_ids: HashSet<u64>,
	pub phishing_emojis: Vec<String>,
	pub silly_emojis: Vec<String>,
}

struct ConfigKey;

impl TypeMapKey for ConfigKey {
	type Value = Arc<BotConfig>;
}

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

			for line in reader.lines().map_while(Result::ok) {
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

			for line in reader.lines().map_while(Result::ok) {
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

			for user_state in users.values_mut() {
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
				let final_quote = random_quote.replace("<chrname>", &msg.author.name);
				let _ = msg.reply(&ctx.http, final_quote).await;
			}
		}
	}
}

async fn start_sticky_worker(ctx: Context, state: Arc<StickyState>) {
	let mut interval = interval(Duration::from_secs(10));
	let channel_id = {
		let data = ctx.data.read().await;
		ChannelId::new(data.get::<ConfigKey>().expect("ConfigKey missing").help_channel_id)
	};

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
				if duration_since_last_msg >= 120 && id_lock.is_none_or(|id| id != last_msg.id) {
					should_delete_id = id_lock.take();
					should_post = true;
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

			for line in reader.lines().map_while(Result::ok) {
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

struct CdnClientKey;

impl TypeMapKey for CdnClientKey {
	type Value = Arc<reqwest::Client>;
}

pub struct SayDraft {
	channel_id: ChannelId,
	title: String,
	description: String,
	color: Option<u32>,
	image_url: String,
	thumbnail_url: String,
	author_name: String,
	author_url: String,
	author_icon_url: String,
	footer_text: String,
	footer_icon_url: String,
	fields: Vec<(String, String, bool)>,
}

impl SayDraft {
	fn new(channel_id: ChannelId) -> Self {
		Self {
			channel_id,
			title: String::new(),
			description: String::new(),
			color: None,
			image_url: String::new(),
			thumbnail_url: String::new(),
			author_name: String::new(),
			author_url: String::new(),
			author_icon_url: String::new(),
			footer_text: String::new(),
			footer_icon_url: String::new(),
			fields: Vec::new(),
		}
	}

	fn is_empty(&self) -> bool {
		self.title.is_empty()
			&& self.description.is_empty()
			&& self.image_url.is_empty()
			&& self.thumbnail_url.is_empty()
			&& self.author_name.is_empty()
			&& self.footer_text.is_empty()
			&& self.fields.is_empty()
	}

	fn total_len(&self) -> usize {
		self.title.chars().count()
			+ self.description.chars().count()
			+ self.author_name.chars().count()
			+ self.footer_text.chars().count()
			+ self
				.fields
				.iter()
				.map(|(name, value, _)| name.chars().count() + value.chars().count())
				.sum::<usize>()
	}

	fn embed(&self) -> CreateEmbed {
		let mut embed = CreateEmbed::new();

		if !self.title.is_empty() {
			embed = embed.title(self.title.as_str());
		}
		if !self.description.is_empty() {
			embed = embed.description(self.description.as_str());
		}
		if let Some(color) = self.color {
			embed = embed.color(color);
		}
		if !self.image_url.is_empty() {
			embed = embed.image(self.image_url.as_str());
		}
		if !self.thumbnail_url.is_empty() {
			embed = embed.thumbnail(self.thumbnail_url.as_str());
		}
		if !self.author_name.is_empty() {
			let mut author = CreateEmbedAuthor::new(self.author_name.as_str());
			if !self.author_url.is_empty() {
				author = author.url(self.author_url.as_str());
			}
			if !self.author_icon_url.is_empty() {
				author = author.icon_url(self.author_icon_url.as_str());
			}
			embed = embed.author(author);
		}
		if !self.footer_text.is_empty() {
			let mut footer = CreateEmbedFooter::new(self.footer_text.as_str());
			if !self.footer_icon_url.is_empty() {
				footer = footer.icon_url(self.footer_icon_url.as_str());
			}
			embed = embed.footer(footer);
		}
		for (name, value, inline) in &self.fields {
			embed = embed.field(name.as_str(), value.as_str(), *inline);
		}

		embed
	}
}

pub struct SayBuilder {
	drafts: Mutex<HashMap<u64, SayDraft>>,
}

struct SayBuilderKey;

impl TypeMapKey for SayBuilderKey {
	type Value = Arc<SayBuilder>;
}

fn parse_hex_color(input: &str) -> Option<u32> {
	let trimmed = input.trim().trim_start_matches('#');
	if trimmed.len() != 6 {
		return None;
	}
	u32::from_str_radix(trimmed, 16).ok()
}

fn is_http_url(url: &str) -> bool {
	url.starts_with("https://") || url.starts_with("http://")
}

fn parse_inline_flag(input: &str) -> bool {
	matches!(
		input.trim().to_ascii_lowercase().as_str(),
		"y" | "yes" | "true" | "1"
	)
}

fn is_image_attachment(attachment: &Attachment) -> bool {
	attachment
		.content_type
		.as_deref()
		.is_some_and(|kind| kind.starts_with("image/"))
}

fn is_cdn_url(url: &str) -> bool {
	reqwest::Url::parse(url)
		.ok()
		.and_then(|parsed| parsed.host_str().map(|host| CDN_ALLOWED_HOSTS.contains(&host)))
		.unwrap_or(false)
}

fn sniff_raster_format(bytes: &[u8]) -> Option<ImageFormat> {
	if bytes.len() < 12 {
		return None;
	}
	match bytes {
		[0xFF, 0xD8, 0xFF, ..] => Some(ImageFormat::Jpeg),
		[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, ..] => Some(ImageFormat::Png),
		[b'G', b'I', b'F', b'8', b'7' | b'9', b'a', ..] => Some(ImageFormat::Gif),
		[b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => {
			Some(ImageFormat::WebP)
		}
		_ => None,
	}
}

fn modal_value<'a>(modal: &'a ModalInteraction, custom_id: &str) -> Option<&'a str> {
	modal.data.components.iter().find_map(|row| {
		row.components.iter().find_map(|component| match component {
			ActionRowComponent::InputText(input) if input.custom_id == custom_id => {
				Some(input.value.as_deref().unwrap_or(""))
			}
			_ => None,
		})
	})
}

async fn handle_trap_message(ctx: &Context, msg: &Message) {
	let config = {
		let data = ctx.data.read().await;
		data.get::<ConfigKey>().cloned().expect("ConfigKey missing")
	};
	if config.owner_ids.contains(&msg.author.id.get()) {
		return;
	}

	if msg.webhook_id.is_some() {
		if let Some(webhook_id) = msg.webhook_id {
			eprintln!(
				"Webhook message detected in trap channel from webhook {}. Deleting message & webhook.",
				webhook_id
			);
			let _ = send_webhook_evidence(ctx, msg).await;
			let _ = msg.delete(&ctx.http).await;

			if let Err(e) = ctx.http.delete_webhook(webhook_id, None).await {
				eprintln!("Failed to delete webhook {}: {}", webhook_id, e);
			}

			rename_trap_channel(ctx).await;
			return;
		}
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

	let (deleted_count, _) = tokio::join!(
		delete_all_user_messages(ctx, guild_id, user_id),
		send_evidence_embed(ctx, &user_name, &user_display, user_id, &avatar_url, &content, msg_timestamp, &attachments),
	);
	println!("Purged {} message(s) from scammer {} ({})", deleted_count, user_name, user_id);

	if is_bot_user {
		eprintln!("Note: user {} is a bot account, attempting ban anyway.", user_id);
	}

	let appeal_url = &config.appeal_url;
	let appeal_text = format!("You have been banned by our anti-bot system. If this was a mistake, please appeal it here: {}", appeal_url);

	if let Err(e) = msg.author.direct_message(&ctx.http, CreateMessage::new().content(appeal_text)).await {
		eprintln!("Failed to send appeal DM to user {} ({}): {}", user_name, user_id, e);
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

#[allow(clippy::too_many_arguments)]
async fn send_evidence_embed(
	ctx: &Context,
	name: &str,
	display: &str,
	uid: UserId,
	avatar: &str,
	content: &str,
	ts: Timestamp,
	attachs: &[Attachment],
) {
	let client = {
		let data = ctx.data.read().await;
		data.get::<CdnClientKey>().cloned().expect("CdnClientKey missing")
	};

	let mut media_tasks = Vec::new();
	for attachment in attachs {
		if is_image_attachment(attachment) {
			media_tasks.push(tokio::spawn(sanitize_image(
				Arc::clone(&client),
				attachment.id,
				attachment.url.clone(),
				attachment.size as usize,
			)));
		}
	}

	let mut sanitized = Vec::new();
	for task in media_tasks {
		if let Ok(Some(media)) = task.await {
			sanitized.push(media);
		}
	}

	let sanitized_ids: HashSet<AttachmentId> = sanitized.iter().map(|m| m.attachment_id).collect();

	let log_ch = {
		let data = ctx.data.read().await;
		ChannelId::new(data.get::<ConfigKey>().expect("ConfigKey missing").evidence_log_channel_id)
	};

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

	if !sanitized.is_empty() {
		embed = embed.image(format!("attachment://{}", sanitized[0].file_name));
	}

	let leftovers: Vec<&Attachment> = attachs.iter().filter(|a| !sanitized_ids.contains(&a.id)).collect();
	if !leftovers.is_empty() {
		let list: Vec<String> = leftovers.iter()
			.map(|a| format!("{} ({} bytes)", a.filename, a.size))
			.collect();
		embed = embed.field("Other Attachments", list.join("\n"), false);
	}

	embed = embed
		.field("Action Taken", "All messages purged + User banned indefinitely", false)
		.timestamp(Timestamp::now());

	let mut message = CreateMessage::new().add_embed(embed);
	for media in sanitized {
		message = message.add_file(CreateAttachment::bytes(media.webp, media.file_name));
	}

	if let Err(e) = log_ch.send_message(&ctx.http, message).await {
		eprintln!("Failed to send evidence embed: {}", e);
	}
}

struct SanitizedMedia {
	attachment_id: AttachmentId,
	file_name: String,
	webp: Vec<u8>,
}

async fn sanitize_image(client: Arc<reqwest::Client>, id: AttachmentId, url: String, size: usize) -> Option<SanitizedMedia> {
	if !is_cdn_url(&url) {
		eprintln!("Attachment {} skipped: host is not on the Discord CDN whitelist", id);
		return None;
	}

	if size > MAX_ATTACHMENT_BYTES {
		eprintln!("Attachment {} skipped: declared size exceeds the {} byte limit", id, MAX_ATTACHMENT_BYTES);
		return None;
	}

	let raw = match download_capped(&client, &url).await {
		Ok(data) => data,
		Err(reason) => {
			eprintln!("Attachment {} skipped: {}", id, reason);
			return None;
		}
	};

	let Some(format) = sniff_raster_format(&raw) else {
		eprintln!("Attachment {} skipped: signature is not a whitelisted raster format", id);
		return None;
	};

	let decode_task = tokio::task::spawn_blocking(move || -> Option<Vec<u8>> {
		let mut limits = image::Limits::default();
		limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
		limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
		limits.max_alloc = Some(MAX_DECODE_ALLOC);

		let mut reader = ImageReader::with_format(Cursor::new(&raw), format);
		reader.limits(limits);

		let decoded = reader.decode().ok()?;
		let rgba = decoded.to_rgba8();
		let (width, height) = rgba.dimensions();

		let mut webp = Vec::new();
		let encoder = WebPEncoder::new_lossless(&mut webp);
		encoder.encode(rgba.as_raw(), width, height, ExtendedColorType::Rgba8).ok()?;

		Some(webp)
	});

	let webp = match timeout(MEDIA_PIPELINE_TIMEOUT, decode_task).await {
		Ok(Ok(Some(data))) => data,
		Ok(Ok(None)) => {
			eprintln!("Attachment {} skipped: decode or encode failed under resource limits", id);
			return None;
		}
		_ => {
			eprintln!("Attachment {} skipped: pipeline panicked or timed out", id);
			return None;
		}
	};

	let file_name = format!("{}.webp", id.get());
	Some(SanitizedMedia {
		attachment_id: id,
		file_name,
		webp,
	})
}

async fn download_capped(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, &'static str> {
	let mut response = client.get(url).send().await.map_err(|_| "download request failed")?;

	if let Some(length) = response.content_length() {
		if length as usize > MAX_ATTACHMENT_BYTES {
			return Err("declared size exceeds the byte limit");
		}
	}

	let mut buffer = Vec::new();
	while let Some(chunk) = response.chunk().await.map_err(|_| "download stream failed")? {
		if buffer.len() + chunk.len() > MAX_ATTACHMENT_BYTES {
			return Err("stream exceeded the byte limit");
		}
		buffer.extend_from_slice(&chunk);
	}

	Ok(buffer)
}

async fn send_webhook_evidence(ctx: &Context, msg: &Message) -> Option<Message> {
	let log_ch = {
		let data = ctx.data.read().await;
		ChannelId::new(data.get::<ConfigKey>().expect("ConfigKey missing").evidence_log_channel_id)
	};
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

	match log_ch.send_message(&ctx.http, CreateMessage::new().add_embed(embed)).await {
		Ok(message) => Some(message),
		Err(e) => {
			eprintln!("Failed to send webhook evidence embed: {}", e);
			None
		}
	}
}

fn is_message_channel(kind: ChannelType) -> bool {
	matches!(
		kind,
		ChannelType::Text
		| ChannelType::PublicThread
		| ChannelType::PrivateThread
	)
}

async fn delete_all_user_messages(ctx: &Context, guild_id: GuildId, user_id: UserId) -> u64 {
	let channels = match guild_id.channels(&ctx.http).await {
		Ok(ch) => ch,
		Err(e) => {
			eprintln!("Failed to get guild channels: {}", e);
			return 0;
		}
	};

	let mut target_channels: Vec<ChannelId> = channels
		.into_iter()
		.filter(|(_, ch)| is_message_channel(ch.kind))
		.map(|(id, _)| id)
		.collect();

	if let Ok(threads_resp) = guild_id.get_active_threads(&ctx.http).await {
		for thread in threads_resp.threads {
			if is_message_channel(thread.kind) {
				target_channels.push(thread.id);
			}
		}
	}

	let mut tasks = tokio::task::JoinSet::new();
	let http = Arc::clone(&ctx.http);

	for channel_id in target_channels {
		let http_clone = Arc::clone(&http);
		tasks.spawn(async move {
			delete_user_messages_in_channel(&http_clone, channel_id, user_id).await
		});
	}

	let mut total_deleted: u64 = 0;
	while let Some(res) = tasks.join_next().await {
		if let Ok(count) = res {
			total_deleted += count;
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
				}
			}
		}
	}

	for id in recent_ids.into_iter().chain(old_ids) {
		match channel_id.delete_message(http, id).await {
			Ok(()) => deleted += 1,
			Err(e) => {
				let err_str = e.to_string();
				if !err_str.contains("10008") {
					eprintln!("Failed to delete message {} in {}: {}", id, channel_id, e);
				}
			}
		}
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

	let channel_id = {
		let data = ctx.data.read().await;
		ChannelId::new(data.get::<ConfigKey>().expect("ConfigKey missing").trap_channel_id)
	};

	match channel_id.edit(&ctx.http, EditChannel::new().name(&new_name)).await {
		Ok(_) => println!("Renamed trap channel to \"{}\"", new_name),
		Err(e) => eprintln!("Failed to rename trap channel: {}", e),
	}
}

fn say_unauthorized_response() -> CreateInteractionResponse {
	CreateInteractionResponse::Message(
		CreateInteractionResponseMessage::new()
			.content("You are not authorized to use this command.")
			.ephemeral(true),
	)
}

async fn say_user_authorized(ctx: &Context, user_id: UserId) -> bool {
	let data = ctx.data.read().await;
	data.get::<ConfigKey>()
		.expect("ConfigKey missing")
		.owner_ids
		.contains(&user_id.get())
}

fn say_notice(text: &'static str) -> CreateInteractionResponseMessage {
	CreateInteractionResponseMessage::new().content(text)
}

fn say_builder_components() -> Vec<CreateActionRow> {
	vec![
		CreateActionRow::Buttons(vec![
			CreateButton::new(SAY_ADD_FIELD_BUTTON)
				.label("Add field")
				.style(ButtonStyle::Primary),
			CreateButton::new(SAY_AUTHOR_BUTTON)
				.label("Author")
				.style(ButtonStyle::Secondary),
			CreateButton::new(SAY_FOOTER_BUTTON)
				.label("Footer")
				.style(ButtonStyle::Secondary),
			CreateButton::new(SAY_EDIT_MAIN_BUTTON)
				.label("Edit main")
				.style(ButtonStyle::Secondary),
		]),
		CreateActionRow::Buttons(vec![
			CreateButton::new(SAY_SEND_BUTTON)
				.label("Send")
				.style(ButtonStyle::Success),
			CreateButton::new(SAY_CANCEL_BUTTON)
				.label("Cancel")
				.style(ButtonStyle::Danger),
		]),
	]
}

fn builder_response_msg(draft: &SayDraft, notice: Option<&'static str>) -> CreateInteractionResponseMessage {
	let mut message = CreateInteractionResponseMessage::new().add_embed(draft.embed());

	if let Some(text) = notice {
		message = message.content(text);
	}

	message.components(say_builder_components())
}

fn with_value(input: CreateInputText, value: &str) -> CreateInputText {
	if value.is_empty() {
		input
	} else {
		input.value(value)
	}
}

fn simple_message_modal(channel_id: ChannelId) -> CreateModal {
	let input = CreateInputText::new(InputTextStyle::Paragraph, "Message content", SAY_CONTENT_INPUT)
		.required(true)
		.max_length(CONTENT_LIMIT as u16);

	CreateModal::new(format!("{SAY_SIMPLE_PREFIX}{}", channel_id.get()), "Send simple message")
		.components(vec![CreateActionRow::InputText(input)])
}

fn embed_main_modal(custom_id: String, draft: Option<&SayDraft>) -> CreateModal {
	let (title, description, color, image, thumbnail) = match draft {
		Some(d) => (
			d.title.as_str(),
			d.description.as_str(),
			d.color.map(|c| format!("#{c:06X}")),
			d.image_url.as_str(),
			d.thumbnail_url.as_str(),
		),
		None => ("", "", None, "", ""),
	};

	let title_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Title", SAY_TITLE_INPUT)
			.required(false)
			.max_length(EMBED_TITLE_LIMIT as u16),
		title,
	);
	let description_input = with_value(
		CreateInputText::new(InputTextStyle::Paragraph, "Description", SAY_DESCRIPTION_INPUT)
			.required(false)
			.max_length(MODAL_INPUT_LIMIT),
		description,
	);
	let color_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Color (hex)", SAY_COLOR_INPUT)
			.required(false)
			.max_length(7)
			.placeholder("#5865F2"),
		color.as_deref().unwrap_or(""),
	);
	let image_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Image URL", SAY_IMAGE_INPUT)
			.required(false)
			.max_length(URL_INPUT_LIMIT),
		image,
	);
	let thumbnail_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Thumbnail URL", SAY_THUMBNAIL_INPUT)
			.required(false)
			.max_length(URL_INPUT_LIMIT),
		thumbnail,
	);

	CreateModal::new(custom_id, "Build embed").components(vec![
		CreateActionRow::InputText(title_input),
		CreateActionRow::InputText(description_input),
		CreateActionRow::InputText(color_input),
		CreateActionRow::InputText(image_input),
		CreateActionRow::InputText(thumbnail_input),
	])
}

fn field_modal() -> CreateModal {
	let name = CreateInputText::new(InputTextStyle::Short, "Field name", SAY_FIELD_NAME_INPUT)
		.required(true)
		.max_length(EMBED_FIELD_NAME_LIMIT as u16);
	let value = CreateInputText::new(InputTextStyle::Paragraph, "Field value", SAY_FIELD_VALUE_INPUT)
		.required(true)
		.max_length(EMBED_FIELD_VALUE_LIMIT as u16);
	let inline = CreateInputText::new(InputTextStyle::Short, "Inline (yes/no)", SAY_FIELD_INLINE_INPUT)
		.required(false)
		.max_length(5)
		.placeholder("no");

	CreateModal::new(SAY_FIELD_MODAL, "Add embed field").components(vec![
		CreateActionRow::InputText(name),
		CreateActionRow::InputText(value),
		CreateActionRow::InputText(inline),
	])
}

fn author_modal(draft: Option<&SayDraft>) -> CreateModal {
	let (name, url, icon) = match draft {
		Some(d) => (d.author_name.as_str(), d.author_url.as_str(), d.author_icon_url.as_str()),
		None => ("", "", ""),
	};

	let name_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Author name", SAY_AUTHOR_NAME_INPUT)
			.required(true)
			.max_length(EMBED_AUTHOR_LIMIT as u16),
		name,
	);
	let url_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Author URL", SAY_AUTHOR_URL_INPUT)
			.required(false)
			.max_length(URL_INPUT_LIMIT),
		url,
	);
	let icon_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Author icon URL", SAY_AUTHOR_ICON_INPUT)
			.required(false)
			.max_length(URL_INPUT_LIMIT),
		icon,
	);

	CreateModal::new(SAY_AUTHOR_MODAL, "Set embed author").components(vec![
		CreateActionRow::InputText(name_input),
		CreateActionRow::InputText(url_input),
		CreateActionRow::InputText(icon_input),
	])
}

fn footer_modal(draft: Option<&SayDraft>) -> CreateModal {
	let (text, icon) = match draft {
		Some(d) => (d.footer_text.as_str(), d.footer_icon_url.as_str()),
		None => ("", ""),
	};

	let text_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Footer text", SAY_FOOTER_TEXT_INPUT)
			.required(true)
			.max_length(EMBED_FOOTER_LIMIT as u16),
		text,
	);
	let icon_input = with_value(
		CreateInputText::new(InputTextStyle::Short, "Footer icon URL", SAY_FOOTER_ICON_INPUT)
			.required(false)
			.max_length(URL_INPUT_LIMIT),
		icon,
	);

	CreateModal::new(SAY_FOOTER_MODAL, "Set embed footer").components(vec![
		CreateActionRow::InputText(text_input),
		CreateActionRow::InputText(icon_input),
	])
}

fn apply_main_inputs(modal: &ModalInteraction, draft: &mut SayDraft) -> Option<&'static str> {
	let mut notice: Option<&'static str> = None;

	draft.title = modal_value(modal, SAY_TITLE_INPUT).unwrap_or("").to_string();
	draft.description = modal_value(modal, SAY_DESCRIPTION_INPUT).unwrap_or("").to_string();

	draft.color = match modal_value(modal, SAY_COLOR_INPUT) {
		Some(raw) if !raw.is_empty() => match parse_hex_color(raw) {
			Some(color) => Some(color),
			None => {
				notice = Some("Color ignored: expected a hex value like 5865F2.");
				None
			}
		},
		_ => None,
	};

	draft.image_url = modal_value(modal, SAY_IMAGE_INPUT).unwrap_or("").to_string();
	if !draft.image_url.is_empty() && !is_http_url(&draft.image_url) {
		notice = Some("Image ignored: the URL must start with https:// or http://.");
		draft.image_url.clear();
	}

	draft.thumbnail_url = modal_value(modal, SAY_THUMBNAIL_INPUT).unwrap_or("").to_string();
	if !draft.thumbnail_url.is_empty() && !is_http_url(&draft.thumbnail_url) {
		notice = Some("Thumbnail ignored: the URL must start with https:// or http://.");
		draft.thumbnail_url.clear();
	}

	notice
}

async fn handle_say_command(ctx: &Context, command: CommandInteraction) {
	if !say_user_authorized(ctx, command.user.id).await {
		let _ = command.create_response(&ctx.http, say_unauthorized_response()).await;
		return;
	}

	let options = vec![
		CreateSelectMenuOption::new("Simple message", "message")
			.description("Plain text message (2000 character limit)"),
		CreateSelectMenuOption::new("Embed", "embed")
			.description("Customizable embed (title, description, color, images, fields...)"),
	];
	let select = CreateSelectMenu::new(SAY_MODE_SELECT_ID, CreateSelectMenuKind::String { options });
	let response = CreateInteractionResponseMessage::new()
		.content("What do you want to send?")
		.ephemeral(true)
		.components(vec![CreateActionRow::SelectMenu(select)]);

	let _ = command.create_response(&ctx.http, CreateInteractionResponse::Message(response)).await;
}

async fn handle_say_component(ctx: &Context, component: ComponentInteraction) {
	if !say_user_authorized(ctx, component.user.id).await {
		let _ = component.create_response(&ctx.http, say_unauthorized_response()).await;
		return;
	}

	match component.data.custom_id.as_str() {
		SAY_MODE_SELECT_ID => {
			let ComponentInteractionDataKind::StringSelect { values } = &component.data.kind else {
				return;
			};
			let response = match values.first().map(String::as_str) {
				Some("message") => {
					CreateInteractionResponse::Modal(simple_message_modal(component.channel_id))
				}
				Some("embed") => CreateInteractionResponse::Modal(embed_main_modal(
					format!("{SAY_EMBED_PREFIX}{}", component.channel_id.get()),
					None,
				)),
				_ => return,
			};
			let _ = component.create_response(&ctx.http, response).await;
		}
		SAY_ADD_FIELD_BUTTON => {
			let at_cap = {
				let data = ctx.data.read().await;
				let builder = data.get::<SayBuilderKey>().expect("SayBuilderKey missing");
				let drafts = builder.drafts.lock().unwrap();
				drafts
					.get(&component.user.id.get())
					.is_some_and(|draft| draft.fields.len() >= EMBED_FIELD_COUNT_LIMIT)
			};

			let response = if at_cap {
				CreateInteractionResponse::UpdateMessage(say_notice(
					"This embed already has the maximum of 25 fields.",
				))
			} else {
				CreateInteractionResponse::Modal(field_modal())
			};
			let _ = component.create_response(&ctx.http, response).await;
		}
		SAY_AUTHOR_BUTTON | SAY_FOOTER_BUTTON | SAY_EDIT_MAIN_BUTTON => {
			let response = {
				let data = ctx.data.read().await;
				let builder = data.get::<SayBuilderKey>().expect("SayBuilderKey missing");
				let drafts = builder.drafts.lock().unwrap();

				match drafts.get(&component.user.id.get()) {
					Some(draft) => {
						let modal = if component.data.custom_id == SAY_AUTHOR_BUTTON {
							author_modal(Some(draft))
						} else if component.data.custom_id == SAY_FOOTER_BUTTON {
							footer_modal(Some(draft))
						} else {
							embed_main_modal(
								format!("{SAY_EDIT_MAIN_PREFIX}{}", draft.channel_id.get()),
								Some(draft),
							)
						};
						CreateInteractionResponse::Modal(modal)
					}
					None => CreateInteractionResponse::UpdateMessage(say_notice(
						"This builder session has expired. Run /say again.",
					)),
				}
			};
			let _ = component.create_response(&ctx.http, response).await;
		}
		SAY_SEND_BUTTON => {
			let (response, draft) = {
				let data = ctx.data.read().await;
				let builder = data.get::<SayBuilderKey>().expect("SayBuilderKey missing");
				let mut drafts = builder.drafts.lock().unwrap();

				match drafts.remove(&component.user.id.get()) {
					None => (
						say_notice("This builder session has expired. Run /say again."),
						None,
					),
					Some(draft) => {
						let problem = if draft.is_empty() {
							Some("There is nothing to send yet. Fill in at least one option or add a field.")
						} else if draft.total_len() > EMBED_TOTAL_LIMIT {
							Some("This embed exceeds the 6000 character total limit. Remove something.")
						} else {
							None
						};

						match problem {
							Some(problem) => {
								let response = builder_response_msg(&draft, Some(problem));
								drafts.insert(component.user.id.get(), draft);
								(response, None)
							}
							None => (say_notice("Sending..."), Some(draft)),
						}
					}
				}
			};

			let _ = component
				.create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(response))
				.await;

			if let Some(draft) = draft {
				match draft
					.channel_id
					.send_message(&ctx.http, CreateMessage::new().add_embed(draft.embed()))
					.await
				{
					Ok(_) => {
						let _ = component
							.edit_response(
								&ctx.http,
								EditInteractionResponse::new().content("Sent."),
							)
							.await;
					}
					Err(e) => {
						eprintln!("Failed to send /say embed: {}", e);
						let _ = component
							.edit_response(
								&ctx.http,
								EditInteractionResponse::new().content(
									"Failed to send the message. I might be missing permissions in the target channel.",
								),
							)
							.await;
					}
				}
			}
		}
		SAY_CANCEL_BUTTON => {
			let response = {
				let data = ctx.data.read().await;
				let builder = data.get::<SayBuilderKey>().expect("SayBuilderKey missing");
				let mut drafts = builder.drafts.lock().unwrap();

				if drafts.remove(&component.user.id.get()).is_some() {
					say_notice("Cancelled.")
				} else {
					say_notice("This builder session has expired. Run /say again.")
				}
			};
			let _ = component
				.create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(response))
				.await;
		}
		_ => {}
	}
}

async fn handle_say_modal(ctx: &Context, modal: ModalInteraction) {
	if !say_user_authorized(ctx, modal.user.id).await {
		let _ = modal.create_response(&ctx.http, say_unauthorized_response()).await;
		return;
	}

	let uid = modal.user.id.get();

	if modal.data.custom_id.starts_with(SAY_SIMPLE_PREFIX) {
		let Some(text) = modal_value(&modal, SAY_CONTENT_INPUT) else {
			return;
		};

		if text.is_empty() || text.chars().count() > CONTENT_LIMIT {
			let _ = modal
				.create_response(
					&ctx.http,
					CreateInteractionResponse::UpdateMessage(say_notice(
						"The message must be between 1 and 2000 characters.",
					)),
				)
				.await;
			return;
		}

		let channel_num = modal
			.data
			.custom_id
			.strip_prefix(SAY_SIMPLE_PREFIX)
			.and_then(|raw| raw.parse::<u64>().ok())
			.unwrap_or(0);

		let _ = modal
			.create_response(
				&ctx.http,
				CreateInteractionResponse::UpdateMessage(say_notice("Sending...")),
			)
			.await;

		match ChannelId::new(channel_num)
			.send_message(&ctx.http, CreateMessage::new().content(text))
			.await
		{
			Ok(_) => {
				let _ = modal
					.edit_response(&ctx.http, EditInteractionResponse::new().content("Sent."))
					.await;
			}
			Err(e) => {
				eprintln!("Failed to send /say message: {}", e);
				let _ = modal
					.edit_response(
						&ctx.http,
						EditInteractionResponse::new().content(
							"Failed to send the message. I might be missing permissions in the target channel.",
						),
					)
					.await;
			}
		}
		return;
	}

	if modal.data.custom_id.starts_with(SAY_EMBED_PREFIX) || modal.data.custom_id.starts_with(SAY_EDIT_MAIN_PREFIX) {
		let response = {
			let data = ctx.data.read().await;
			let builder = data.get::<SayBuilderKey>().expect("SayBuilderKey missing");
			let mut drafts = builder.drafts.lock().unwrap();

			if modal.data.custom_id.starts_with(SAY_EMBED_PREFIX) {
				let channel_num = modal
					.data
					.custom_id
					.strip_prefix(SAY_EMBED_PREFIX)
					.and_then(|raw| raw.parse::<u64>().ok())
					.unwrap_or(0);
				drafts.insert(uid, SayDraft::new(ChannelId::new(channel_num)));
			}

			match drafts.get_mut(&uid) {
				None => say_notice("This builder session has expired. Run /say again."),
				Some(draft) => {
					let notice = apply_main_inputs(&modal, draft);
					let notice = notice.or_else(|| {
						if draft.is_empty() {
							Some("Fill in at least one option, or add fields, an author, or a footer.")
						} else {
							None
						}
					});
					builder_response_msg(draft, notice)
				}
			}
		};

		let _ = modal
			.create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(response))
			.await;
		return;
	}

	let response = {
		let data = ctx.data.read().await;
		let builder = data.get::<SayBuilderKey>().expect("SayBuilderKey missing");
		let mut drafts = builder.drafts.lock().unwrap();

		match drafts.get_mut(&uid) {
			None => say_notice("This builder session has expired. Run /say again."),
			Some(draft) => match modal.data.custom_id.as_str() {
				SAY_FIELD_MODAL => {
					if draft.fields.len() >= EMBED_FIELD_COUNT_LIMIT {
						builder_response_msg(draft, Some("This embed already has the maximum of 25 fields."))
					} else {
						let name = modal_value(&modal, SAY_FIELD_NAME_INPUT).unwrap_or("");
						let value = modal_value(&modal, SAY_FIELD_VALUE_INPUT).unwrap_or("");
						let inline = modal_value(&modal, SAY_FIELD_INLINE_INPUT)
							.is_some_and(parse_inline_flag);
						draft.fields.push((name.to_string(), value.to_string(), inline));
						builder_response_msg(draft, Some("Field added."))
					}
				}
				SAY_AUTHOR_MODAL => {
					draft.author_name =
						modal_value(&modal, SAY_AUTHOR_NAME_INPUT).unwrap_or("").to_string();
					draft.author_url =
						modal_value(&modal, SAY_AUTHOR_URL_INPUT).unwrap_or("").to_string();
					draft.author_icon_url =
						modal_value(&modal, SAY_AUTHOR_ICON_INPUT).unwrap_or("").to_string();

					let mut notice: Option<&'static str> = None;
					if !draft.author_url.is_empty() && !is_http_url(&draft.author_url) {
						notice = Some("Author URL ignored: it must start with https:// or http://.");
						draft.author_url.clear();
					}
					if !draft.author_icon_url.is_empty() && !is_http_url(&draft.author_icon_url) {
						notice =
							Some("Author icon ignored: it must start with https:// or http://.");
						draft.author_icon_url.clear();
					}

					builder_response_msg(draft, notice)
				}
				SAY_FOOTER_MODAL => {
					draft.footer_text =
						modal_value(&modal, SAY_FOOTER_TEXT_INPUT).unwrap_or("").to_string();
					draft.footer_icon_url =
						modal_value(&modal, SAY_FOOTER_ICON_INPUT).unwrap_or("").to_string();

					let mut notice: Option<&'static str> = None;
					if !draft.footer_icon_url.is_empty() && !is_http_url(&draft.footer_icon_url) {
						notice =
							Some("Footer icon ignored: it must start with https:// or http://.");
						draft.footer_icon_url.clear();
					}

					builder_response_msg(draft, notice)
				}
				_ => say_notice("Unknown builder form."),
			},
		}
	};

	let _ = modal
		.create_response(&ctx.http, CreateInteractionResponse::UpdateMessage(response))
		.await;
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
		let config = {
			let data = ctx.data.read().await;
			data.get::<ConfigKey>().cloned().expect("ConfigKey missing")
		};

		if msg.author.bot || msg.guild_id.is_none_or(|id| id.get() != config.target_guild_id) {
			return;
		}

		let data = ctx.data.read().await;
		let protect = data.get::<PhishingKey>().cloned().expect("PhishingProtect missing");
		let sticky = data.get::<StickyKey>().cloned().expect("StickyState missing");
		drop(data);

		if msg.channel_id.get() == config.trap_channel_id {
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
				let index: usize = rng_range(0..config.phishing_emojis.len());
				let emoji = &config.phishing_emojis[index];
				let response = format!("{} bad link! {}", msg.author.mention(), emoji);
				let _ = msg.channel_id.say(&ctx.http, response).await;
			}
			return;
		}

		if msg.channel_id.get() == config.help_channel_id {
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
		let rate = if msg.channel_id.get() == config.help_channel_id { 0.0001 } else { 0.001 };
		if should_show(rate) {
			let index: usize = rng_range(0..config.silly_emojis.len());
			let emoji = &config.silly_emojis[index];
			let _ = msg.reply(&ctx.http, emoji).await;
			if let Ok(reaction) = ReactionType::try_from(emoji.as_str()) {
				let _ = msg.react(&ctx.http, reaction).await;
			}
		}

		if msg.channel_id.get() == config.silly_channel_id {
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

		if is_special_day() && msg.author.id.get() != config.gacha_ignore_user_id {
			if let Some((tier_name, outcome)) = perform_gacha_pull(msg.author.id.get(), msg.id.get(), &msg.content, &ROLE_GACHA_POOL) {
				let role_id_raw = outcome.role_id;
				let role_id = RoleId::new(role_id_raw);
				let guild_id = msg.guild_id.unwrap();

				let has_role = msg.member.as_ref().is_some_and(|m| m.roles.contains(&role_id));

				if !has_role && ctx.http.add_member_role(guild_id, msg.author.id, role_id, Some("Role gacha from Silly bot")).await.is_ok() {
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

		let say_command = CreateCommand::new(SAY_COMMAND_NAME)
			.description("Make the bot say something (owners only)")
			.kind(CommandType::ChatInput);

		for guild in &ready.guilds {
			let _ = guild.id.set_commands(&ctx.http, vec![say_command.clone()]).await;
		}
	}

	async fn interaction_create(&self, ctx: Context, interaction: Interaction) {
		match interaction {
			Interaction::Command(command) => {
				if command.data.name == SAY_COMMAND_NAME {
					handle_say_command(&ctx, command).await;
				}
			}
			Interaction::Component(component) => handle_say_component(&ctx, component).await,
			Interaction::Modal(modal) => handle_say_modal(&ctx, modal).await,
			_ => {}
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

	let config = Arc::new(BotConfig {
		target_guild_id: parse_env("GUILD_ID"),
		trap_channel_id: parse_env("TRAP_CHANNEL_ID"),
		evidence_log_channel_id: parse_env("EVIDENCE_LOG_CHANNEL_ID"),
		silly_channel_id: parse_env("SILLY_CHANNEL_ID"),
		help_channel_id: parse_env("HELP_CHANNEL_ID"),
		gacha_ignore_user_id: parse_env("GACHA_IGNORE_USER_ID"),
		appeal_url: parse_env("APPEAL_URL"),
		sticky_enabled: parse_env("STICKY_ENABLED"),
		owner_ids: parse_env_list::<u64>("OWNER_IDS").into_iter().collect(),
		phishing_emojis: parse_env_list("PHISHING_EMOJIS"),
		silly_emojis: parse_env_list("SILLY_EMOJIS")
	});

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
		enabled: config.sticky_enabled,
		last_sticky_id: Mutex::new(None),
		last_author_id: Mutex::new(None)
	});

	let safe_words = Arc::new(SafeWordsList {
		words: RwLock::new(Vec::new())
	});
	safe_words.load("safe_english_words.txt");

	let ban_tracker = Arc::new(BanTracker {
		pending: Mutex::new(HashSet::new())
	});

	let cdn_client = Arc::new(
		reqwest::Client::builder()
			.redirect(reqwest::redirect::Policy::none())
			.connect_timeout(Duration::from_secs(10))
			.timeout(Duration::from_secs(20))
			.build()
			.expect("Failed to build the CDN HTTP client")
	);

	let say_builder = Arc::new(SayBuilder {
		drafts: Mutex::new(HashMap::new())
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

	let token = std::env::var("TOKEN").expect("Missing TOKEN environment variable.");
	let intents = GatewayIntents::GUILD_MESSAGES
		| GatewayIntents::MESSAGE_CONTENT
		| GatewayIntents::GUILD_MEMBERS;

	let mut client = Client::builder(&token, intents)
		.event_handler(Handler)
		.await
		.expect("Err creating client");

	{
		let mut data = client.data.write().await;
		data.insert::<ConfigKey>(Arc::clone(&config));
		data.insert::<PhishingKey>(protect);
		data.insert::<StickyKey>(sticky_state);
		data.insert::<StoryLinesKey>(story_lines);
		data.insert::<SillyReplyQueueKey>(story_queue);
		data.insert::<SafeWordsKey>(safe_words);
		data.insert::<BanTrackerKey>(ban_tracker);
		data.insert::<CdnClientKey>(cdn_client);
		data.insert::<SayBuilderKey>(say_builder);
	}

	if let Err(why) = client.start().await {
		println!("Client error: {:?}", why);
	}
}
