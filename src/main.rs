use serenity::{
	async_trait,
	model::{gateway::Ready, channel::Message},
	prelude::*
};
use std::{
	collections::HashSet,
	fs::{self, File},
	io::{BufRead, BufReader, BufWriter, copy},
	sync::{Arc, RwLock},
	time::Duration
};
use tokio::time::{interval, MissedTickBehavior};

pub struct PhishingProtect {
	pub links: RwLock<HashSet<String>>,
}

impl PhishingProtect {
	pub fn load(&self, path: &str) {
		if let Ok(file) = File::open(path) {
			let reader = BufReader::new(file);
			let mut new_links = HashSet::new();

			for line in reader.lines().filter_map(Result::ok) {
				let trimmed = line.trim();
				if !trimmed.is_empty() {
					new_links.insert(trimmed.to_lowercase());
				}
			}

			new_links.shrink_to_fit();

			let mut write_lock = self.links.write().unwrap();
			*write_lock = new_links;
			println!("Phishing list updated. Total links: {}", write_lock.len());
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
			let links = protect.links.read().unwrap();
			msg.content.split_whitespace().any(|word| {
				links.contains(&word.to_lowercase())
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

async fn start_hourly_download(url: String, filename: String, protect: Arc<PhishingProtect>) {
	let mut timer = interval(Duration::from_secs(3600));
	timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

	let tmp_filename = format!("{}.tmp", filename);
	let agent = ureq::agent();

	loop {
		timer.tick().await;
		println!("Downloading {}...", url);

		let result: Result<(), Box<dyn std::error::Error>> = (|| {
			let mut response = agent.get(&url).call()?;
			let mut reader = response.body_mut().as_reader();

			let file = File::create(&tmp_filename)?;
			let mut writer = BufWriter::new(file);
			
			copy(&mut reader, &mut writer)?;
			writer.into_inner()?;

			fs::rename(&tmp_filename, &filename)?;
			protect.load(&filename);

			Ok(())
		})();

		if let Err(e) = result {
			eprintln!("Hourly update failed: {}", e);
			let _ = fs::remove_file(&tmp_filename);
		} else {
			println!("Successfully downloaded: {}", filename);
		}
	}
}

#[tokio::main]
async fn main() {
	dotenvy::dotenv().ok();

	let protect = Arc::new(PhishingProtect {
		links: RwLock::new(HashSet::new())
	});
	protect.load("phishing.txt");

	let protect_clone = Arc::clone(&protect);
	tokio::spawn(async move {
		start_hourly_download(
			// big thanks to https://github.com/Phishing-Database/Phishing.Database
			"https://phish.co.za/latest/phishing-domains-ACTIVE.txt".to_string(), 
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
