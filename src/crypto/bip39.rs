use crate::crypto::aes::{compute_sha256, CryptoError};
use rand::rngs::OsRng;
use rand::RngCore;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// Official 2,048-word BIP-39 English wordlist (`bitcoin/bips/bip-0039/english.txt`),
/// sorted lexicographically for $O(\log_2 2048) = 11$-step binary search and 11-bit index packing.
pub static BIP39_ENGLISH_WORDLIST: [&str; 2048] = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd",
    "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire",
    "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid",
    "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
    "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst",
    "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual",
    "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear",
    "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed",
    "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist",
    "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete",
    "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt",
    "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome",
    "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony",
    "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
    "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin",
    "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better",
    "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter",
    "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
    "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus",
    "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
    "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief",
    "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown",
    "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle",
    "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz",
    "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can",
    "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital",
    "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash",
    "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught",
    "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal",
    "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child",
    "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon",
    "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean",
    "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog",
    "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast",
    "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come",
    "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress",
    "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral",
    "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin",
    "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl",
    "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop",
    "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry",
    "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve",
    "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring",
    "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide",
    "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay",
    "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit",
    "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy",
    "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary",
    "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur",
    "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display",
    "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft",
    "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip",
    "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty",
    "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy",
    "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either",
    "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else",
    "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable",
    "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine",
    "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire",
    "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error",
    "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil",
    "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse",
    "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand",
    "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow",
    "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family",
    "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue",
    "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female",
    "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file",
    "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first",
    "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee",
    "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam",
    "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork",
    "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame",
    "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit",
    "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery",
    "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate",
    "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture",
    "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue",
    "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown",
    "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid",
    "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy",
    "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health",
    "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden",
    "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday",
    "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host",
    "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry",
    "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify",
    "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index",
    "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit",
    "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane",
    "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite",
    "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar",
    "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup",
    "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten",
    "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake",
    "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law",
    "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left",
    "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson",
    "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like",
    "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan",
    "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge",
    "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine",
    "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage",
    "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine",
    "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix",
    "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media",
    "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry",
    "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind",
    "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed",
    "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster",
    "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor",
    "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum",
    "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin",
    "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect",
    "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next",
    "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable",
    "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak",
    "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean",
    "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic",
    "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose",
    "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original",
    "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over",
    "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace",
    "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot",
    "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment",
    "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people",
    "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical",
    "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer",
    "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please",
    "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police",
    "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato",
    "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare",
    "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison",
    "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote",
    "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull",
    "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose",
    "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question",
    "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio",
    "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate",
    "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall",
    "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region",
    "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember",
    "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace",
    "report", "require", "rescue", "resemble", "resist", "resource", "response", "result",
    "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib",
    "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple",
    "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance",
    "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber",
    "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail",
    "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi",
    "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme",
    "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub",
    "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek",
    "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service",
    "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell",
    "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop",
    "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side",
    "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since",
    "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin",
    "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim",
    "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack",
    "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar",
    "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special",
    "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split",
    "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square",
    "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand",
    "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still",
    "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street",
    "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit",
    "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun",
    "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise",
    "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear",
    "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system",
    "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste",
    "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test",
    "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this",
    "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt",
    "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today",
    "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue",
    "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss",
    "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic",
    "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial",
    "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly",
    "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey",
    "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical",
    "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair",
    "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until",
    "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge",
    "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague",
    "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle",
    "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel",
    "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage",
    "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice",
    "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall",
    "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave",
    "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird",
    "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip",
    "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink",
    "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder",
    "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist",
    "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone",
    "zoo",
];

/// Normalizes a recovery seed phrase or passphrase per BIP-39 (`B6`):
/// 1. Applies Unicode Normalization Form Compatibility Decomposition (`NFKD`).
/// 2. Lowercases ASCII characters (`to_ascii_lowercase()`).
/// 3. Trims leading/trailing whitespace and collapses all internal whitespace runs (`\t`, `\r\n`,
///    multiple spaces, non-breaking spaces) into single ASCII spaces `" "`.
pub fn normalize_seed_phrase_nfkd(phrase: &str) -> String {
    let decomposed: String = phrase.nfkd().collect();
    let lowered = decomposed.to_ascii_lowercase();
    let words: Vec<&str> = lowered.split_whitespace().collect();
    words.join(" ")
}

/// Computes the Levenshtein edit distance between two ASCII strings for typo suggestion (`A4`).
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let m = a_bytes.len();
    let n = b_bytes.len();
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(a_bytes[i - 1] != b_bytes[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Finds the closest word in `BIP39_ENGLISH_WORDLIST` by Levenshtein edit distance.
pub fn closest_bip39_word(typo: &str) -> &'static str {
    let mut best_word = BIP39_ENGLISH_WORDLIST[0];
    let mut best_dist = usize::MAX;
    for &candidate in &BIP39_ENGLISH_WORDLIST {
        let d = levenshtein_distance(typo, candidate);
        if d < best_dist {
            best_dist = d;
            best_word = candidate;
            if d <= 1 {
                break;
            }
        }
    }
    best_word
}

/// Validates a BIP-39 English mnemonic phrase (`A4`, `B6`):
/// 1. Normalizes via `normalize_seed_phrase_nfkd`.
/// 2. Checks that word count is `12`, `15`, `18`, `21`, or `24`.
/// 3. Verifies every word belongs to `BIP39_ENGLISH_WORDLIST` (suggesting the closest word on typo).
/// 4. Unpacks the 11-bit indices into entropy bytes + checksum bits and verifies the `ENT / 32`-bit
///    `SHA-256(entropy)` checksum.
///
/// Returns the canonical NFKD-normalized space-separated mnemonic string on success.
pub fn validate_bip39_mnemonic(phrase: &str) -> Result<String, CryptoError> {
    let canonical = normalize_seed_phrase_nfkd(phrase);
    if canonical.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial(
            "BIP-39 mnemonic phrase cannot be empty".into(),
        ));
    }

    let words: Vec<&str> = canonical.split(' ').collect();
    let word_count = words.len();
    let (ent_bits, cs_bits) = match word_count {
        12 => (128usize, 4usize),
        15 => (160usize, 5usize),
        18 => (192usize, 6usize),
        21 => (224usize, 7usize),
        24 => (256usize, 8usize),
        _ => {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "invalid BIP-39 mnemonic word count {word_count} (expected 12, 15, 18, 21, or 24 words)"
            )));
        }
    };

    let mut indices = Vec::with_capacity(word_count);
    for word in &words {
        match BIP39_ENGLISH_WORDLIST.binary_search(word) {
            Ok(idx) => indices.push(idx as u16),
            Err(_) => {
                let suggestion = closest_bip39_word(word);
                return Err(CryptoError::InvalidKeyMaterial(format!(
                    "unknown BIP-39 word '{word}' (did you mean '{suggestion}'?)"
                )));
            }
        }
    }

    // Unpack 11-bit word indices into a bit stream of length `ent_bits + cs_bits`.
    let total_bits = ent_bits + cs_bits;
    let ent_bytes_len = ent_bits / 8;
    let mut entropy = vec![0u8; ent_bytes_len];
    let mut checksum_val: u8 = 0;

    for bit_idx in 0..total_bits {
        let word_pos = bit_idx / 11;
        let bit_in_word = 10 - (bit_idx % 11);
        let bit = ((indices[word_pos] >> bit_in_word) & 1) as u8;
        if bit_idx < ent_bits {
            let byte_pos = bit_idx / 8;
            let bit_in_byte = 7 - (bit_idx % 8);
            entropy[byte_pos] |= bit << bit_in_byte;
        } else {
            checksum_val = (checksum_val << 1) | bit;
        }
    }

    let hash = compute_sha256(&entropy);
    entropy.zeroize();
    let expected_checksum = hash[0] >> (8 - cs_bits);
    if checksum_val != expected_checksum {
        return Err(CryptoError::InvalidKeyMaterial(
            "BIP-39 mnemonic checksum verification failed (possible word typo or transposition)"
                .into(),
        ));
    }

    Ok(canonical)
}

/// Validates either a strict BIP-39 mnemonic (when the input has 12, 15, 18, 21, or 24 words)
/// or a custom high-entropy recovery passphrase (`>= 12` characters after NFKD normalization).
pub fn validate_recovery_seed_phrase_or_passphrase(phrase: &str) -> Result<String, CryptoError> {
    let canonical = normalize_seed_phrase_nfkd(phrase);
    if canonical.is_empty() {
        return Err(CryptoError::InvalidKeyMaterial(
            "recovery seed phrase cannot be empty".into(),
        ));
    }
    let word_count = canonical.split(' ').count();
    if matches!(word_count, 12 | 15 | 18 | 21 | 24) {
        return validate_bip39_mnemonic(&canonical);
    }
    if canonical.len() < 12 {
        return Err(CryptoError::InvalidKeyMaterial(
            "recovery passphrase is too short (use a 12/24-word BIP-39 mnemonic or >= 12-char passphrase)".into(),
        ));
    }
    Ok(canonical)
}

/// Encodes raw entropy bytes (`16`, `20`, `24`, `28`, or `32` bytes) into a standard BIP-39 English mnemonic.
pub fn entropy_to_bip39_mnemonic(entropy: &[u8]) -> Result<String, CryptoError> {
    let ent_bits = entropy.len() * 8;
    let cs_bits = match ent_bits {
        128 => 4usize,
        160 => 5usize,
        192 => 6usize,
        224 => 7usize,
        256 => 8usize,
        _ => {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "invalid BIP-39 entropy length {} bytes (expected 16, 20, 24, 28, or 32)",
                entropy.len()
            )));
        }
    };

    let hash = compute_sha256(entropy);
    let total_bits = ent_bits + cs_bits;
    let word_count = total_bits / 11;
    let mut words = Vec::with_capacity(word_count);

    for w in 0..word_count {
        let mut idx: usize = 0;
        for b in 0..11 {
            let bit_idx = w * 11 + b;
            let bit = if bit_idx < ent_bits {
                let byte_pos = bit_idx / 8;
                let bit_in_byte = 7 - (bit_idx % 8);
                ((entropy[byte_pos] >> bit_in_byte) & 1) as usize
            } else {
                let cs_bit_idx = bit_idx - ent_bits;
                ((hash[0] >> (7 - cs_bit_idx)) & 1) as usize
            };
            idx = (idx << 1) | bit;
        }
        words.push(BIP39_ENGLISH_WORDLIST[idx]);
    }

    Ok(words.join(" "))
}

/// Generates a fresh cryptographically random 12-, 15-, 18-, 21-, or 24-word BIP-39 English mnemonic from `OsRng`.
pub fn generate_bip39_mnemonic(word_count: usize) -> Result<String, CryptoError> {
    let ent_bytes_len = match word_count {
        12 => 16usize,
        15 => 20usize,
        18 => 24usize,
        21 => 28usize,
        24 => 32usize,
        _ => {
            return Err(CryptoError::InvalidKeyMaterial(format!(
                "unsupported BIP-39 word count {word_count} (expected 12, 15, 18, 21, or 24)"
            )));
        }
    };
    let mut entropy = vec![0u8; ent_bytes_len];
    OsRng.fill_bytes(&mut entropy);
    let res = entropy_to_bip39_mnemonic(&entropy);
    entropy.zeroize();
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bip39_canonical_vectors_and_typo_detection() {
        // Canonical all-zero 128-bit entropy -> 11 "abandon" + "about"
        let zero_16 = [0u8; 16];
        let m12 = entropy_to_bip39_mnemonic(&zero_16).expect("12-word mnemonic");
        assert_eq!(
            m12,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(validate_bip39_mnemonic(&m12).unwrap(), m12);

        // Canonical all-zero 256-bit entropy -> 23 "abandon" + "art"
        let zero_32 = [0u8; 32];
        let m24 = entropy_to_bip39_mnemonic(&zero_32).expect("24-word mnemonic");
        assert_eq!(
            m24,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        );
        assert_eq!(validate_bip39_mnemonic(&m24).unwrap(), m24);

        // NFKD + whitespace normalization
        let messy = "  ABANDON\t\tabandon\r\nAbandon   abandon abandon abandon abandon abandon abandon abandon abandon ABOUT ";
        assert_eq!(validate_bip39_mnemonic(messy).unwrap(), m12);

        // Bad checksum detection (12x "abandon")
        let bad_cs = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        let err = validate_bip39_mnemonic(bad_cs).unwrap_err().to_string();
        assert!(err.contains("checksum verification failed"), "got: {err}");

        // Unknown word with Levenshtein suggestion
        let typo = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon aboot";
        let err_typo = validate_bip39_mnemonic(typo).unwrap_err().to_string();
        assert!(
            err_typo.contains("unknown BIP-39 word 'aboot'"),
            "got: {err_typo}"
        );
        assert!(err_typo.contains("did you mean"), "got: {err_typo}");
    }
}
