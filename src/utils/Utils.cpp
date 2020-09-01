//
// Created by nova on 8/19/20.
//

#include <iomanip>
#include "Utils.h"

std::string Utils::StringProcess::ToLowerCase(const std::string& str)
{
	std::string copy = str;
	std::transform(copy.begin(), copy.end(), copy.begin(), [](unsigned char c) { return std::tolower(c); });
	return copy;
}

std::string Utils::Codec::Base64UrlEncode(const std::string& in)
{
	std::string out;
	int val = 0, valb = -6;
	size_t len = in.length();
	for (unsigned int i = 0; i < len; i++)
	{
		unsigned char c = in[i];
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0)
		{
			out.push_back(base64UrlTable[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6)
	{
		out.push_back(base64UrlTable[((val << 8) >> (valb + 8)) & 0x3F]);
	}
	return out;
}

std::string Utils::Codec::Base64UrlDecode(const std::string& in)
{
	std::string out;
	std::vector<int> T(256, -1);
	for (unsigned int i = 0; i < 64; i++)
		T[base64UrlTable[i]] = i;
	
	int val = 0, valb = -8;
	for (unsigned char c : in)
	{
		if (T[c] == -1)
			break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0)
		{
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}

std::string Utils::Codec::Base64UrlEncode(const std::shared_ptr<const std::vector<std::byte>>& in)
{
	std::string out;
	int val = 0, valb = -6;
	size_t len = in->size();
	for (unsigned int i = 0; i < len; i++)
	{
		auto c = (unsigned char)(*in)[i];
		val = (val << 8) + c;
		valb += 8;
		while (valb >= 0)
		{
			out.push_back(base64UrlTable[(val >> valb) & 0x3F]);
			valb -= 6;
		}
	}
	if (valb > -6)
	{
		out.push_back(base64UrlTable[((val << 8) >> (valb + 8)) & 0x3F]);
	}
	return out;
}

std::string Utils::Codec::Base64UrlDecode(const std::shared_ptr<const std::vector<std::byte>>& in)
{
	std::string out;
	std::vector<int> T(256, -1);
	for (unsigned int i = 0; i < 64; i++)
		T[base64UrlTable[i]] = i;
	
	int val = 0, valb = -8;
	for (unsigned long i = 0; i < in->size(); ++i)
	{
		if (T[(unsigned int)(*in)[i]] == -1)
			break;
		val = (val << 6) + T[(unsigned int)(*in)[i]];
		valb += 6;
		if (valb >= 0)
		{
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}

std::shared_ptr<std::vector<std::byte>> Utils::StringProcess::StringToByteVec(const std::string& str)
{
	const auto* cstr = str.c_str();
	return std::make_shared<std::vector<std::byte>>((std::byte*)cstr, (std::byte*)cstr + str.size());
}

std::string Utils::StringProcess::ByteVecToString(const std::shared_ptr<const std::vector<std::byte>>& vec)
{
	const auto* ptr = vec->data();
	return std::string((char*)ptr, (char*)ptr + vec->size());
}

std::string Utils::Time::UnixTimeToRFC3339(long utcTime, int timeZone)
{
	if (timeZone < -12 or timeZone > 14)
		return std::string();
	
	/* Get time zone shift */
	long shift = timeZone * 60 * 60;
	
	/* Get "%Y-%m-%d %I:%M:%S" */
	std::time_t tmp = utcTime + shift;
	std::tm* t = std::gmtime(&tmp);
	std::stringstream ss;
	ss << std::put_time(t, "%Y-%m-%d %H:%M:%S");
	std::string str = ss.str();
	
	/* To rfc-3339 format */
	auto pos = str.find(' ');
	std::string date = str.substr(0, pos);
	std::string time = str.substr(pos + 1, str.size());
	std::string zonePart = timeZone < 0 ? std::to_string(-timeZone) : std::to_string(timeZone);
	if (timeZone < 0)
		zonePart = std::to_string(-timeZone);
	else
		zonePart = std::to_string(timeZone);
	if (zonePart.size() == 1)
		zonePart = "0" + zonePart;
	if (timeZone < 0)
		zonePart = "-" + zonePart + ":00";
	else
		zonePart = "+" + zonePart + ":00";
	
	return date + "T" + time + zonePart;
}

int Utils::Time::localTimeZoneUTC()
{
	auto now = std::time(nullptr);
	auto const tm = *std::localtime(&now);
	std::ostringstream os;
	os << std::put_time(&tm, "%z");
	std::string s = os.str();
	
	int h = std::stoi(s.substr(0, 3), nullptr, 10);
	int m = std::stoi(s[0] + s.substr(3), nullptr, 10);
	
	return (h * 3600 + m * 60) / 60 / 60;
}

bool Utils::Domain::RootZoneIsValid(const std::string& zone)
{
	std::string copy = Utils::StringProcess::ToLowerCase(zone);
	for (const auto& name : RootZones())
	{
		if (name == copy)
			return true;
	}
	return false;
}

const std::vector<std::string>& Utils::Domain::RootZones()
{
	static std::vector<std::string> zones{"com", "net", "org", "aaa", "aarp", "abarth", "abb", "abbott", "abbvie",
	                                      "abc", "able", "abogado", "abudhabi", "ac", "academy", "accenture",
	                                      "accountant", "accountants", "aco", "actor", "ad", "adac", "ads", "adult",
	                                      "ae", "aeg", "aero", "aetna", "af", "afamilycompany", "afl", "africa", "ag",
	                                      "agakhan", "agency", "ai", "aig", "airbus", "airforce", "airtel", "akdn",
	                                      "al", "alfaromeo", "alibaba", "alipay", "allfinanz", "allstate", "ally",
	                                      "alsace", "alstom", "am", "amazon", "americanexpress", "americanfamily",
	                                      "amex", "amfam", "amica", "amsterdam", "analytics", "android", "anquan",
	                                      "anz", "ao", "aol", "apartments", "app", "apple", "aq", "aquarelle", "ar",
	                                      "arab", "aramco", "archi", "army", "arpa", "art", "arte", "as", "asda",
	                                      "asia", "associates", "at", "athleta", "attorney", "au", "auction", "audi",
	                                      "audible", "audio", "auspost", "author", "auto", "autos", "avianca", "aw",
	                                      "aws", "ax", "axa", "az", "azure", "ba", "baby", "baidu", "banamex",
	                                      "bananarepublic", "band", "bank", "bar", "barcelona", "barclaycard",
	                                      "barclays", "barefoot", "bargains", "baseball", "basketball", "bauhaus",
	                                      "bayern", "bb", "bbc", "bbt", "bbva", "bcg", "bcn", "bd", "be", "beats",
	                                      "beauty", "beer", "bentley", "berlin", "best", "bestbuy", "bet", "bf", "bg",
	                                      "bh", "bharti", "bi", "bible", "bid", "bike", "bing", "bingo", "bio", "biz",
	                                      "bj", "black", "blackfriday", "blockbuster", "blog", "bloomberg", "blue",
	                                      "bm", "bms", "bmw", "bn", "bnpparibas", "bo", "boats", "boehringer", "bofa",
	                                      "bom", "bond", "boo", "book", "booking", "bosch", "bostik", "boston", "bot",
	                                      "boutique", "box", "br", "bradesco", "bridgestone", "broadway", "broker",
	                                      "brother", "brussels", "bs", "bt", "budapest", "bugatti", "build", "builders",
	                                      "business", "buy", "buzz", "bv", "bw", "by", "bz", "bzh", "ca", "cab", "cafe",
	                                      "cal", "call", "calvinklein", "cam", "camera", "camp", "cancerresearch",
	                                      "canon", "capetown", "capital", "capitalone", "car", "caravan", "cards",
	                                      "care", "career", "careers", "cars", "casa", "case", "caseih", "cash",
	                                      "casino", "cat", "catering", "catholic", "cba", "cbn", "cbre", "cbs", "cc",
	                                      "cd", "ceb", "center", "ceo", "cern", "cf", "cfa", "cfd", "cg", "ch",
	                                      "chanel", "channel", "charity", "chase", "chat", "cheap", "chintai",
	                                      "christmas", "chrome", "church", "ci", "cipriani", "circle", "cisco",
	                                      "citadel", "citi", "citic", "city", "cityeats", "ck", "cl", "claims",
	                                      "cleaning", "click", "clinic", "clinique", "clothing", "cloud", "club",
	                                      "clubmed", "cm", "cn", "co", "coach", "codes", "coffee", "college", "cologne",
	                                      "comcast", "commbank", "community", "company", "compare", "computer",
	                                      "comsec", "condos", "construction", "consulting", "contact", "contractors",
	                                      "cooking", "cookingchannel", "cool", "coop", "corsica", "country", "coupon",
	                                      "coupons", "courses", "cpa", "cr", "credit", "creditcard", "creditunion",
	                                      "cricket", "crown", "crs", "cruise", "cruises", "csc", "cu", "cuisinella",
	                                      "cv", "cw", "cx", "cy", "cymru", "cyou", "cz", "dabur", "dad", "dance",
	                                      "data", "date", "dating", "datsun", "day", "dclk", "dds", "de", "deal",
	                                      "dealer", "deals", "degree", "delivery", "dell", "deloitte", "delta",
	                                      "democrat", "dental", "dentist", "desi", "design", "dev", "dhl", "diamonds",
	                                      "diet", "digital", "direct", "directory", "discount", "discover", "dish",
	                                      "diy", "dj", "dk", "dm", "dnp", "do", "docs", "doctor", "dog", "domains",
	                                      "dot", "download", "drive", "dtv", "dubai", "duck", "dunlop", "dupont",
	                                      "durban", "dvag", "dvr", "dz", "earth", "eat", "ec", "eco", "edeka", "edu",
	                                      "education", "ee", "eg", "email", "emerck", "energy", "engineer",
	                                      "engineering", "enterprises", "epson", "equipment", "er", "ericsson", "erni",
	                                      "es", "esq", "estate", "et", "etisalat", "eu", "eurovision", "eus", "events",
	                                      "exchange", "expert", "exposed", "express", "extraspace", "fage", "fail",
	                                      "fairwinds", "faith", "family", "fan", "fans", "farm", "farmers", "fashion",
	                                      "fast", "fedex", "feedback", "ferrari", "ferrero", "fi", "fiat", "fidelity",
	                                      "fido", "film", "final", "finance", "financial", "fire", "firestone",
	                                      "firmdale", "fish", "fishing", "fit", "fitness", "fj", "fk", "flickr",
	                                      "flights", "flir", "florist", "flowers", "fly", "fm", "fo", "foo", "food",
	                                      "foodnetwork", "football", "ford", "forex", "forsale", "forum", "foundation",
	                                      "fox", "fr", "free", "fresenius", "frl", "frogans", "frontdoor", "frontier",
	                                      "ftr", "fujitsu", "fujixerox", "fun", "fund", "furniture", "futbol", "fyi",
	                                      "ga", "gal", "gallery", "gallo", "gallup", "game", "games", "gap", "garden",
	                                      "gay", "gb", "gbiz", "gd", "gdn", "ge", "gea", "gent", "genting", "george",
	                                      "gf", "gg", "ggee", "gh", "gi", "gift", "gifts", "gives", "giving", "gl",
	                                      "glade", "glass", "gle", "global", "globo", "gm", "gmail", "gmbh", "gmo",
	                                      "gmx", "gn", "godaddy", "gold", "goldpoint", "golf", "goo", "goodyear",
	                                      "goog", "google", "gop", "got", "gov", "gp", "gq", "gr", "grainger",
	                                      "graphics", "gratis", "green", "gripe", "grocery", "group", "gs", "gt", "gu",
	                                      "guardian", "gucci", "guge", "guide", "guitars", "guru", "gw", "gy", "hair",
	                                      "hamburg", "hangout", "haus", "hbo", "hdfc", "hdfcbank", "health",
	                                      "healthcare", "help", "helsinki", "here", "hermes", "hgtv", "hiphop",
	                                      "hisamitsu", "hitachi", "hiv", "hk", "hkt", "hm", "hn", "hockey", "holdings",
	                                      "holiday", "homedepot", "homegoods", "homes", "homesense", "honda", "horse",
	                                      "hospital", "host", "hosting", "hot", "hoteles", "hotels", "hotmail", "house",
	                                      "how", "hr", "hsbc", "ht", "hu", "hughes", "hyatt", "hyundai", "ibm", "icbc",
	                                      "ice", "icu", "id", "ie", "ieee", "ifm", "ikano", "il", "im", "imamat",
	                                      "imdb", "immo", "immobilien", "in", "inc", "industries", "infiniti", "info",
	                                      "ing", "ink", "institute", "insurance", "insure", "int", "intel",
	                                      "international", "intuit", "investments", "io", "ipiranga", "iq", "ir",
	                                      "irish", "is", "ismaili", "ist", "istanbul", "it", "itau", "itv", "iveco",
	                                      "jaguar", "java", "jcb", "jcp", "je", "jeep", "jetzt", "jewelry", "jio",
	                                      "jll", "jm", "jmp", "jnj", "jo", "jobs", "joburg", "jot", "joy", "jp",
	                                      "jpmorgan", "jprs", "juegos", "juniper", "kaufen", "kddi", "ke",
	                                      "kerryhotels", "kerrylogistics", "kerryproperties", "kfh", "kg", "kh", "ki",
	                                      "kia", "kim", "kinder", "kindle", "kitchen", "kiwi", "km", "kn", "koeln",
	                                      "komatsu", "kosher", "kp", "kpmg", "kpn", "kr", "krd", "kred", "kuokgroup",
	                                      "kw", "ky", "kyoto", "kz", "la", "lacaixa", "lamborghini", "lamer",
	                                      "lancaster", "lancia", "land", "landrover", "lanxess", "lasalle", "lat",
	                                      "latino", "latrobe", "law", "lawyer", "lb", "lc", "lds", "lease", "leclerc",
	                                      "lefrak", "legal", "lego", "lexus", "lgbt", "li", "lidl", "life",
	                                      "lifeinsurance", "lifestyle", "lighting", "like", "lilly", "limited", "limo",
	                                      "lincoln", "linde", "link", "lipsy", "live", "living", "lixil", "lk", "llc",
	                                      "llp", "loan", "loans", "locker", "locus", "loft", "lol", "london", "lotte",
	                                      "lotto", "love", "lpl", "lplfinancial", "lr", "ls", "lt", "ltd", "ltda", "lu",
	                                      "lundbeck", "lupin", "luxe", "luxury", "lv", "ly", "ma", "macys", "madrid",
	                                      "maif", "maison", "makeup", "man", "management", "mango", "map", "market",
	                                      "marketing", "markets", "marriott", "marshalls", "maserati", "mattel", "mba",
	                                      "mc", "mckinsey", "md", "me", "med", "media", "meet", "melbourne", "meme",
	                                      "memorial", "men", "menu", "merckmsd", "metlife", "mg", "mh", "miami",
	                                      "microsoft", "mil", "mini", "mint", "mit", "mitsubishi", "mk", "ml", "mlb",
	                                      "mls", "mm", "mma", "mn", "mo", "mobi", "mobile", "moda", "moe", "moi", "mom",
	                                      "monash", "money", "monster", "mormon", "mortgage", "moscow", "moto",
	                                      "motorcycles", "mov", "movie", "mp", "mq", "mr", "ms", "msd", "mt", "mtn",
	                                      "mtr", "mu", "museum", "mutual", "mv", "mw", "mx", "my", "mz", "na", "nab",
	                                      "nagoya", "name", "nationwide", "natura", "navy", "nba", "nc", "ne", "nec",
	                                      "netbank", "netflix", "network", "neustar", "new", "newholland", "news",
	                                      "next", "nextdirect", "nexus", "nf", "nfl", "ng", "ngo", "nhk", "ni", "nico",
	                                      "nike", "nikon", "ninja", "nissan", "nissay", "nl", "no", "nokia",
	                                      "northwesternmutual", "norton", "now", "nowruz", "nowtv", "np", "nr", "nra",
	                                      "nrw", "ntt", "nu", "nyc", "nz", "obi", "observer", "off", "office",
	                                      "okinawa", "olayan", "olayangroup", "oldnavy", "ollo", "om", "omega", "one",
	                                      "ong", "onl", "online", "onyourside", "ooo", "open", "oracle", "orange",
	                                      "organic", "origins", "osaka", "otsuka", "ott", "ovh", "pa", "page",
	                                      "panasonic", "paris", "pars", "partners", "parts", "party", "passagens",
	                                      "pay", "pccw", "pe", "pet", "pf", "pfizer", "pg", "ph", "pharmacy", "phd",
	                                      "philips", "phone", "photo", "photography", "photos", "physio", "pics",
	                                      "pictet", "pictures", "pid", "pin", "ping", "pink", "pioneer", "pizza", "pk",
	                                      "pl", "place", "play", "playstation", "plumbing", "plus", "pm", "pn", "pnc",
	                                      "pohl", "poker", "politie", "porn", "post", "pr", "pramerica", "praxi",
	                                      "press", "prime", "pro", "prod", "productions", "prof", "progressive",
	                                      "promo", "properties", "property", "protection", "pru", "prudential", "ps",
	                                      "pt", "pub", "pw", "pwc", "py", "qa", "qpon", "quebec", "quest", "qvc",
	                                      "racing", "radio", "raid", "re", "read", "realestate", "realtor", "realty",
	                                      "recipes", "red", "redstone", "redumbrella", "rehab", "reise", "reisen",
	                                      "reit", "reliance", "ren", "rent", "rentals", "repair", "report",
	                                      "republican", "rest", "restaurant", "review", "reviews", "rexroth", "rich",
	                                      "richardli", "ricoh", "ril", "rio", "rip", "rmit", "ro", "rocher", "rocks",
	                                      "rodeo", "rogers", "room", "rs", "rsvp", "ru", "rugby", "ruhr", "run", "rw",
	                                      "rwe", "ryukyu", "sa", "saarland", "safe", "safety", "sakura", "sale",
	                                      "salon", "samsclub", "samsung", "sandvik", "sandvikcoromant", "sanofi", "sap",
	                                      "sarl", "sas", "save", "saxo", "sb", "sbi", "sbs", "sc", "sca", "scb",
	                                      "schaeffler", "schmidt", "scholarships", "school", "schule", "schwarz",
	                                      "science", "scjohnson", "scot", "sd", "se", "search", "seat", "secure",
	                                      "security", "seek", "select", "sener", "services", "ses", "seven", "sew",
	                                      "sex", "sexy", "sfr", "sg", "sh", "shangrila", "sharp", "shaw", "shell",
	                                      "shia", "shiksha", "shoes", "shop", "shopping", "shouji", "show", "showtime",
	                                      "shriram", "si", "silk", "sina", "singles", "site", "sj", "sk", "ski", "skin",
	                                      "sky", "skype", "sl", "sling", "sm", "smart", "smile", "sn", "sncf", "so",
	                                      "soccer", "social", "softbank", "software", "sohu", "solar", "solutions",
	                                      "song", "sony", "soy", "space", "sport", "spot", "spreadbetting", "sr", "srl",
	                                      "ss", "st", "stada", "staples", "star", "statebank", "statefarm", "stc",
	                                      "stcgroup", "stockholm", "storage", "store", "stream", "studio", "study",
	                                      "style", "su", "sucks", "supplies", "supply", "support", "surf", "surgery",
	                                      "suzuki", "sv", "swatch", "swiftcover", "swiss", "sx", "sy", "sydney",
	                                      "systems", "sz", "tab", "taipei", "talk", "taobao", "target", "tatamotors",
	                                      "tatar", "tattoo", "tax", "taxi", "tc", "tci", "td", "tdk", "team", "tech",
	                                      "technology", "tel", "temasek", "tennis", "teva", "tf", "tg", "th", "thd",
	                                      "theater", "theatre", "tiaa", "tickets", "tienda", "tiffany", "tips", "tires",
	                                      "tirol", "tj", "tjmaxx", "tjx", "tk", "tkmaxx", "tl", "tm", "tmall", "tn",
	                                      "to", "today", "tokyo", "tools", "top", "toray", "toshiba", "total", "tours",
	                                      "town", "toyota", "toys", "tr", "trade", "trading", "training", "travel",
	                                      "travelchannel", "travelers", "travelersinsurance", "trust", "trv", "tt",
	                                      "tube", "tui", "tunes", "tushu", "tv", "tvs", "tw", "tz", "ua", "ubank",
	                                      "ubs", "ug", "uk", "unicom", "university", "uno", "uol", "ups", "us", "uy",
	                                      "uz", "va", "vacations", "vana", "vanguard", "vc", "ve", "vegas", "ventures",
	                                      "verisign", "versicherung", "vet", "vg", "vi", "viajes", "video", "vig",
	                                      "viking", "villas", "vin", "vip", "virgin", "visa", "vision", "viva", "vivo",
	                                      "vlaanderen", "vn", "vodka", "volkswagen", "volvo", "vote", "voting", "voto",
	                                      "voyage", "vu", "vuelos", "wales", "walmart", "walter", "wang", "wanggou",
	                                      "watch", "watches", "weather", "weatherchannel", "webcam", "weber", "website",
	                                      "wed", "wedding", "weibo", "weir", "wf", "whoswho", "wien", "wiki",
	                                      "williamhill", "win", "windows", "wine", "winners", "wme", "wolterskluwer",
	                                      "woodside", "work", "works", "world", "wow", "ws", "wtc", "wtf", "xbox",
	                                      "xerox", "xfinity", "xihuan", "xin", "xn--11b4c3d", "xn--1ck2e1b",
	                                      "xn--1qqw23a", "xn--2scrj9c", "xn--30rr7y", "xn--3bst00m", "xn--3ds443g",
	                                      "xn--3e0b707e", "xn--3hcrj9c", "xn--3oq18vl8pn36a", "xn--3pxu8k",
	                                      "xn--42c2d9a", "xn--45br5cyl", "xn--45brj9c", "xn--45q11c", "xn--4gbrim",
	                                      "xn--54b7fta0cc", "xn--55qw42g", "xn--55qx5d", "xn--5su34j936bgsg",
	                                      "xn--5tzm5g", "xn--6frz82g", "xn--6qq986b3xl", "xn--80adxhks", "xn--80ao21a",
	                                      "xn--80aqecdr1a", "xn--80asehdb", "xn--80aswg", "xn--8y0a063a", "xn--90a3ac",
	                                      "xn--90ae", "xn--90ais", "xn--9dbq2a", "xn--9et52u", "xn--9krt00a",
	                                      "xn--b4w605ferd", "xn--bck1b9a5dre4c", "xn--c1avg", "xn--c2br7g",
	                                      "xn--cck2b3b", "xn--cckwcxetd", "xn--cg4bki", "xn--clchc0ea0b2g2a9gcd",
	                                      "xn--czr694b", "xn--czrs0t", "xn--czru2d", "xn--d1acj3b", "xn--d1alf",
	                                      "xn--e1a4c", "xn--eckvdtc9d", "xn--efvy88h", "xn--fct429k", "xn--fhbei",
	                                      "xn--fiq228c5hs", "xn--fiq64b", "xn--fiqs8s", "xn--fiqz9s", "xn--fjq720a",
	                                      "xn--flw351e", "xn--fpcrj9c3d", "xn--fzc2c9e2c", "xn--fzys8d69uvgm",
	                                      "xn--g2xx48c", "xn--gckr3f0f", "xn--gecrj9c", "xn--gk3at1e", "xn--h2breg3eve",
	                                      "xn--h2brj9c", "xn--h2brj9c8c", "xn--hxt814e", "xn--i1b6b1a6a2e",
	                                      "xn--imr513n", "xn--io0a7i", "xn--j1aef", "xn--j1amh", "xn--j6w193g",
	                                      "xn--jlq480n2rg", "xn--jlq61u9w7b", "xn--jvr189m", "xn--kcrx77d1x4a",
	                                      "xn--kprw13d", "xn--kpry57d", "xn--kput3i", "xn--l1acc", "xn--lgbbat1ad8j",
	                                      "xn--mgb9awbf", "xn--mgba3a3ejt", "xn--mgba3a4f16a", "xn--mgba7c0bbn0a",
	                                      "xn--mgbaakc7dvf", "xn--mgbaam7a8h", "xn--mgbab2bd", "xn--mgbah1a3hjkrd",
	                                      "xn--mgbai9azgqp6j", "xn--mgbayh7gpa", "xn--mgbbh1a", "xn--mgbbh1a71e",
	                                      "xn--mgbc0a9azcg", "xn--mgbca7dzdo", "xn--mgbcpq6gpa1a", "xn--mgberp4a5d4ar",
	                                      "xn--mgbgu82a", "xn--mgbi4ecexp", "xn--mgbpl2fh", "xn--mgbt3dhd",
	                                      "xn--mgbtx2b", "xn--mgbx4cd0ab", "xn--mix891f", "xn--mk1bu44c", "xn--mxtq1m",
	                                      "xn--ngbc5azd", "xn--ngbe9e0a", "xn--ngbrx", "xn--node", "xn--nqv7f",
	                                      "xn--nqv7fs00ema", "xn--nyqy26a", "xn--o3cw4h", "xn--ogbpf8fl", "xn--otu796d",
	                                      "xn--p1acf", "xn--p1ai", "xn--pgbs0dh", "xn--pssy2u", "xn--q7ce6a",
	                                      "xn--q9jyb4c", "xn--qcka1pmc", "xn--qxa6a", "xn--qxam", "xn--rhqv96g",
	                                      "xn--rovu88b", "xn--rvc1e0am3e", "xn--s9brj9c", "xn--ses554g", "xn--t60b56a",
	                                      "xn--tckwe", "xn--tiq49xqyj", "xn--unup4y", "xn--vermgensberater-ctb",
	                                      "xn--vermgensberatung-pwb", "xn--vhquv", "xn--vuq861b",
	                                      "xn--w4r85el8fhu5dnra", "xn--w4rs40l", "xn--wgbh1c", "xn--wgbl6a",
	                                      "xn--xhq521b", "xn--xkc2al3hye2a", "xn--xkc2dl3a5ee0h", "xn--y9a3aq",
	                                      "xn--yfro4i67o", "xn--ygbi2ammx", "xn--zfr164b", "xxx", "xyz", "yachts",
	                                      "yahoo", "yamaxun", "yandex", "ye", "yodobashi", "yoga", "yokohama", "you",
	                                      "youtube", "yt", "yun", "za", "zappos", "zara", "zero", "zip", "zm", "zone",
	                                      "zuerich", "zw"};
	return zones;
}

std::string Utils::Domain::ExtractBaseDomain(const std::string& domain)
{
	std::vector<std::string> parts = Utils::StringProcess::SplitString(domain, '.');
	if (parts.size() < 2)
		return std::string();
	else
		return parts[parts.size() - 2] + "." + parts.back();
}

bool Utils::Domain::IsValid(const std::string& domain, bool enableWildcard)
{
	std::string validChar = "abcdefghijklmnopqrstuvwxyz0123456789-_";
	std::string copy = Utils::StringProcess::ToLowerCase(domain);
	/* If start or end with '.' */
	if (copy.at(0) == '.' or copy.at(copy.size() - 1) == '.')
		return false;
	
	/* If has continuous '.' */
	for (unsigned long i = 1; i < copy.size(); ++i)
	{
		if (copy.at(i) == '.' and copy.at(i) == copy.at(i - 1))
			return false;
	}
	
	if (copy.size() > 254)    /* Check total length */
		return false;
	
	std::vector<std::string> parts = Utils::StringProcess::SplitString(copy, '.');
	
	if (enableWildcard)     /* If wildcard, check if start with "*." */
	{
		if (parts.at(0) == std::string("*"))
			parts.erase(parts.begin());
	}
	
	if (!RootZoneIsValid(parts.back()))     /* Validate root zone */
		return false;
	else
		parts.pop_back();
	
	/* Validate parts */
	for (const auto& part: parts)
	{
		if (part.size() > 63)
			return false;
		if (part.at(0) == '-' or part.at(part.size() - 1) == '-')
			return false;
		for (auto c : part)
		{
			if ((int)validChar.find(c, 0) == -1)
				return false;
		}
	}
	return true;
}

std::string Utils::Domain::RemoveLowestLevelSub(const std::string& domainName, bool ignoreWildcardAsterisk)
{
	auto domainParts = Utils::StringProcess::SplitString(domainName, '.');
	
	if (ignoreWildcardAsterisk and domainParts.at(0) == "*")
		domainParts.erase(domainParts.begin()); // Remove the lowest level sub domain
	
	if (domainParts.size() <= 2)
		return std::string();
	
	domainParts.erase(domainParts.begin()); // Remove the lowest level sub domain
	std::string newDomainName;
	for (const auto& part : domainParts)
		newDomainName += (part + ".");
	newDomainName.pop_back();
	return newDomainName;
}

bool Utils::Domain::IsWildcard(const std::string& domainName)
{
	if (!IsValid(domainName, true))
		return false;
	if (domainName[0] == '*' and domainName[1] == '.')
		return true;
	else
		return false;
}

std::vector<std::string> Utils::StringProcess::SplitString(const std::string& s, char delimiter)
{
	std::vector<std::string> tokens;
	std::string token;
	std::istringstream tokenStream(s);
	while (std::getline(tokenStream, token, delimiter))
	{
		if (!token.empty())
			tokens.push_back(token);
	}
	return tokens;
}

std::vector<std::string> Utils::StringProcess::SplitString(const std::string& s, const std::string& delimiter)
{
	size_t pos_start = 0;
	unsigned long pos_end = 0;
	std::vector<std::string> tokens;
	
	while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos)
	{
		std::string token = s.substr(pos_start, pos_end - pos_start);
		pos_start = pos_end + delimiter.length();
		tokens.push_back(token);
	}
	
	tokens.push_back(s.substr(pos_start));
	return tokens;
}

std::string Utils::StringProcess::StringToJson(const std::string& jString, Json::Value* json)
{
	Json::CharReaderBuilder builder;
	Json::CharReader* reader = builder.newCharReader();
	Json::Value jsonResult;
	std::string jsonParseErrors;
	auto ok = reader->parse(jString.c_str(), jString.c_str() + jString.size(), json, &jsonParseErrors);
	delete reader;
	if (!ok)
		return jsonParseErrors;
	else
		return std::string();
}

bool Utils::EmailIsValid(const std::string& email)
{
	std::regex pattern(R"((\w+)(\.|_)?(\w*)@(\w+)(\.(\w+))+)");
	return std::regex_match(email, pattern);
}

int Utils::ExecuteShell(const std::string& command)
{
	return system((command+" 1>/dev/null 2>&1").c_str());
}
