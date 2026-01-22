use serenity::{
	async_trait,
	model::{
		channel::Message,
		gateway::Ready,
		id::*
	},
	prelude::*
};
use std::{
	collections::HashSet,
	fs::{self, File},
	io::{BufRead, BufReader},
	sync::{Arc, Mutex, RwLock},
	process::Command,
	time::{Duration, Instant}
};
use rand::{
	Rng,
	distr::uniform::{SampleRange, SampleUniform}
};
use tokio::time::{interval, MissedTickBehavior};

pub struct PhishingProtect {
	pub set: RwLock<HashSet<String>>,
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

struct PhishingKey;

impl TypeMapKey for PhishingKey {
	type Value = Arc<PhishingProtect>;
}

struct Handler {
	last_sticky_id: Mutex<Option<MessageId>>,
	last_author_id: Mutex<Option<UserId>>,
	last_activity_time: Mutex<Instant>
}

fn should_reply(rate: f64) -> bool {
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
		let protect = data.get::<PhishingKey>()
			.expect("PhishingProtect not found in TypeMap")
			.clone();
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
		}

		let help_channel_id = 1248143441242619955;
		if msg.channel_id.get() == help_channel_id {
			let sticky_message = r#"# :warning: BEFORE ASKING A QUESTION :warning:
- Having runtime errors? Install [Hachimi Edge](https://hachimi.noccu.art).
- Check for your issue in [Troubleshooting](https://hachimi.noccu.art/docs/hachimi/troubleshooting).
- Check the pins and backread messsages in this channel.

You will be intentionally ignored if the sources mentioned above cover your issue.
Bugs instead of tech issue? Check <#1248143380437930085>."#;
			let now = Instant::now();
			let mut should_delete_id = None;
			let mut should_post = false;

			{
				let mut last_author = self.last_author_id.lock().unwrap();
				let mut last_activity = self.last_activity_time.lock().unwrap();
				let mut id_lock = self.last_sticky_id.lock().unwrap();
	
				if let Some(prev_author) = *last_author {
					if prev_author != msg.author.id {
						*last_activity = now;
						should_delete_id = id_lock.take();
					}
				}

				if id_lock.is_none() {
					let idle_duration = now.duration_since(*last_activity);
					if idle_duration.as_secs() >= 180 {
						should_post = true;
					}
				} else {
					*last_activity = now;
				}
				*last_author = Some(msg.author.id);
			}
	
			if let Some(id) = should_delete_id {
				let _ = msg.channel_id.delete_message(&ctx.http, id).await;
				let mut last_activity = self.last_activity_time.lock().unwrap();
				*last_activity = now;
			}

			if should_post {
				if let Ok(new_msg) = msg.channel_id.say(&ctx.http, sticky_message).await {
					let mut id_lock = self.last_sticky_id.lock().unwrap();
					*id_lock = Some(new_msg.id);
				}
			}
		}

		// let content_lower = msg.content.to_lowercase();
		// 0.2% if on help channel otherwise 3%
		let rate = if msg.channel_id.get() == help_channel_id { 0.002 } else { 0.03 };
		if should_reply(rate) {
			let silly_emojis = [
				"<a:sildance:1462056515056828499>",
				"<:sillier:1463878217197682865>",
				"<a:Sillymambo:1463878469610897485>",
				"<:stillinstare:1463878652402860228>"
			];
			
			let index: usize = rng_range(0..silly_emojis.len());
			let emoji = silly_emojis[index];
			let _ = msg.reply(&ctx.http, emoji).await;
		}
	}

	async fn ready(&self, _: Context, ready: Ready) {
		println!("{} is connected!", ready.user.name);
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

	let protect_clone = Arc::clone(&protect);
	tokio::spawn(async move {
		start_daily_download(
			// big thanks to https://github.com/Phishing-Database/Phishing.Database
			"https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-links-ACTIVE.txt".to_string(), 
			"phishing.txt".to_string(),
			protect_clone
		).await;
	});

	let token = std::env::var("TOKEN").expect("Expected a token in the environment");
	let intents = GatewayIntents::GUILD_MESSAGES
		| GatewayIntents::MESSAGE_CONTENT;

	let mut client = Client::builder(&token, intents)
		.event_handler(Handler {
			last_sticky_id: Mutex::new(None),
			last_author_id: Mutex::new(None),
			last_activity_time: Mutex::new(Instant::now())
		})
		.await
		.expect("Err creating client");

	{
		let mut data = client.data.write().await;
		data.insert::<PhishingKey>(protect);
	}

	if let Err(why) = client.start().await {
		println!("Client error: {:?}", why);
	}
}
