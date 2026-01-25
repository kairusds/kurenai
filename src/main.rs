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
	sync::{Arc, Mutex, RwLock},
	process::Command,
	time::Duration
};
use rand::{
	Rng,
	distr::uniform::{SampleRange, SampleUniform}
};
use tokio::time::{interval, MissedTickBehavior};

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
- Check for your issue in [Troubleshooting](https://hachimi.noccu.art/docs/hachimi/troubleshooting).
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
		if msg.author.bot {
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
	}

	async fn ready(&self, ctx: Context, ready: Ready) {
		println!("{} is connected!", ready.user.name);
		let data = ctx.data.read().await;
		let sticky_state = data.get::<StickyKey>().cloned().expect("StickyKey missing");

		let ctx_clone = ctx.clone();
		tokio::spawn(async move {
			start_sticky_worker(ctx_clone, sticky_state).await;
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

	let sticky_state = Arc::new(StickyState {
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
		| GatewayIntents::MESSAGE_CONTENT;

	let mut client = Client::builder(&token, intents)
		.event_handler(Handler)
		.await
		.expect("Err creating client");

	{
		let mut data = client.data.write().await;
		data.insert::<PhishingKey>(protect);
		data.insert::<StickyKey>(sticky_state);
	}

	if let Err(why) = client.start().await {
		println!("Client error: {:?}", why);
	}
}
