use serenity::{
	async_trait,
	model::{gateway::Ready, channel::Message},
	prelude::*
};
use std::{
	collections::HashSet,
	fs::{self, File},
	io::{BufRead, BufReader},
	sync::{Arc, RwLock},
	process::Command,
	time::Duration
};

use tokio::time::{interval, MissedTickBehavior};

pub struct PhishingProtect {
	pub domains: RwLock<HashSet<String>>,
}

impl PhishingProtect {
	pub fn load(&self, path: &str) {
		if let Ok(file) = File::open(path) {
			let reader = BufReader::new(file);
			let mut new_domains = HashSet::new();

			for line in reader.lines().filter_map(Result::ok) {
				let trimmed = line.trim();
				if !trimmed.is_empty() {
					new_domains.insert(trimmed.to_lowercase());
				}
			}

			new_domains.shrink_to_fit();

			let mut write_lock = self.domains.write().unwrap();
			*write_lock = new_domains;
			println!("Phishing list updated. Total domains: {}", write_lock.len());
		}
	}
}

struct PhishingKey;

impl TypeMapKey for PhishingKey {
	type Value = Arc<PhishingProtect>;
}

struct Handler;

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
			let domains = protect.domains.read().unwrap();
			msg.content.split_whitespace().any(|word| {
				let word_lower = word.to_lowercase();

				let domain_to_check = if word_lower.starts_with("http") {
					let stripped = word_lower
						.trim_start_matches("https://")
						.trim_start_matches("http://");
					stripped.split('/').next().unwrap_or(stripped)
				} else {
					&word_lower
				};
				let clean_domain = domain_to_check.trim_end_matches(|c: char| {
					c == '.' || c == '/' || c == '?' || c == '!' || c == ','
				});
				domains.contains(clean_domain)
			})
		};

		if is_phishing {
			if let Err(e) = msg.delete(&ctx.http).await {
				eprintln!("Failed to delete phishing message: {}", e);
			} else {
				let response = format!("{} ban this guy", msg.author.mention());
				if let Err(e) = msg.channel_id.say(&ctx.http, response).await {
					eprintln!("Failed to send: {}", e);
				}
			}
		}

		if msg.content.to_lowercase().contains("silly") {
			let emoji = "<a:sildance:1462056515056828499>";
			if let Err(why) = msg.reply(&ctx.http, emoji).await {
				println!("Error sending message: {:?}", why);
			}
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
		domains: RwLock::new(HashSet::new())
	});
	protect.load("phishing.txt");

	let protect_clone = Arc::clone(&protect);
	tokio::spawn(async move {
		start_daily_download(
			// big thanks to https://github.com/Phishing-Database/Phishing.Database
			"https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/refs/heads/master/phishing-domains-ACTIVE.txt".to_string(), 
			"phishing.txt".to_string(),
			protect_clone
		).await;
	});

	let token = std::env::var("TOKEN").expect("Expected a token in the environment");
	let intents = GatewayIntents::GUILD_MESSAGES 
		| GatewayIntents::DIRECT_MESSAGES 
		| GatewayIntents::MESSAGE_CONTENT;

	let mut client = Client::builder(&token, intents)
		.event_handler(Handler)
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
