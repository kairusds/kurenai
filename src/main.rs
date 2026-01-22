use serenity::{
	async_trait,
	model::{
		channel::Message,
		gateway::Ready,
		id::MessageId
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

struct Handler {
	last_sticky_update: Mutex<Instant>,
	last_sticky_id: Mutex<Option<MessageId>>
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

		let help_channel_id = 1248143441242619955;
		if msg.channel_id.get() == help_channel_id {
			let mut should_update = false;

			{
				let mut last_update = self.last_sticky_update.lock().unwrap();
				if Instant::now().duration_since(*last_update).as_secs() >= 10 {
					*last_update = Instant::now();
					should_update = true;
				}
			}

			if should_update {
				let sticky_message = r#"**CHECK THE PINS FIRST BEFORE ASKING A QUESTION**
** 1. Having runtime errors? Install Hachimi Edge from **<#1248142172004548620>.
** 2. Did you press "Restart" on the shutdown menu after installing Hachimi?**
** 3. Do you play Riot games? If so, Vanguard is preventing you to play Umamusume with Hachimi installed.**
** 4. If none of these cover the answers to the issues you're facing, ping the Helpdesk role.**

** You will be intentionally ignored if a fix is already available for your problems on the pinned messages, the site or previous messages in this channel.**

Check <#1248143380437930085> for known issues/problems."#;

				let old_id = {
					let mut id_lock = self.last_sticky_id.lock().unwrap();
					id_lock.take()
				};

				if let Some(id) = old_id {
					let _ = msg.channel_id.delete_message(&ctx.http, id).await;
				}

				if let Ok(new_msg) = msg.channel_id.say(&ctx.http, sticky_message).await {
					let mut id_lock = self.last_sticky_id.lock().unwrap();
					*id_lock = Some(new_msg.id);
				}
			}
		}

		if msg.content.to_lowercase().contains("sil") {
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
		.event_handler(Handler {
			last_sticky_update: Mutex::new(Instant::now()),
			last_sticky_id: Mutex::new(None)
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
