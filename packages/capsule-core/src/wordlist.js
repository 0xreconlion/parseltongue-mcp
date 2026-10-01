'use strict';

/**
 * Wordlist for generated decrypt codes.
 *
 * WHY HAND-CURATED, AND NOT DERIVED
 *
 * The first attempt filtered /usr/share/dict/american-english to 4-6 letter lowercase words and
 * dropped anything within edit distance 1 of a word already kept. That produced 5272 entries and
 * a 40-word sample containing `bldg`, `cocci`, `cumuli`, `baleen`, `befog`, `aslant` and `fief` —
 * words most people cannot spell from hearing them, which is disqualifying for a code whose
 * entire job is to survive being read aloud over a second channel. A couple of other hits were
 * words nobody wants to read out in a work setting. It also depended on a system file that will
 * not exist on another machine.
 *
 * SELECTION RULES
 *
 *   - 3 to 7 letters, lowercase a-z
 *   - common and concrete: spellable on first hearing, by a non-native speaker
 *   - no homophone pairs (no bear/bare, flour/flower, steel/steal, knight/night)
 *   - nothing crude, medical, or awkward to say out loud
 *   - no digits, no hyphens; the code separator is the hyphen
 *
 * THE ONE-LETTER RULE IS ENFORCED, NOT CLAIMED
 *
 * No two published entries may differ by a single letter, so one mis-hearing cannot silently
 * produce a different valid word. The hand-written source below does NOT satisfy that on its own
 * — a first draft of this file asserted the rule in a comment while containing 198 violating
 * pairs (`bat`/`cat`, `bean`/`bear`, `amber`/`ember`). Rather than hunt them by eye, the filter
 * below applies the rule and `DROPPED` records what it removed, so the invariant is a property of
 * the module instead of a promise in a comment. A test asserts zero surviving pairs.
 *
 * Keep the themed groups when adding words — they are for human maintenance. The filter decides
 * what actually ships.
 *
 * ENTROPY IS COMPUTED FROM THE PUBLISHED ARRAY AT RUNTIME, never asserted in a comment. See
 * `codeEntropyBits` in sealed.js. Add or remove a word and the measured figure moves with it.
 */

const WORDS = [
  // animals
  'ant', 'ape', 'bass', 'bat', 'bear', 'bee', 'bird', 'bison', 'boar', 'bull',
  'calf', 'carp', 'cat', 'clam', 'cobra', 'colt', 'coral', 'cow', 'crab', 'crane',
  'crow', 'deer', 'dingo', 'dove', 'duck', 'eagle', 'eel', 'elk', 'emu', 'falcon',
  'fawn', 'ferret', 'finch', 'fish', 'flea', 'fox', 'frog', 'gecko', 'goat', 'goose',
  'gull', 'hare', 'hawk', 'heron', 'horse', 'hound', 'ibex', 'koala', 'lamb', 'lark',
  'lemur', 'lion', 'llama', 'lynx', 'macaw', 'mole', 'moose', 'moth', 'mouse', 'mule',
  'newt', 'otter', 'owl', 'ox', 'panda', 'perch', 'pig', 'pony', 'puffin', 'puma',
  'quail', 'rabbit', 'ram', 'raven', 'robin', 'seal', 'shark', 'sheep', 'skunk', 'sloth',
  'snail', 'snake', 'sparrow', 'squid', 'stork', 'swan', 'tiger', 'toad', 'trout', 'tuna',
  'turtle', 'viper', 'walrus', 'wasp', 'whale', 'wolf', 'wombat', 'worm', 'yak', 'zebra',

  // plants and food
  'acorn', 'almond', 'apple', 'bamboo', 'barley', 'basil', 'bean', 'beet', 'berry', 'birch',
  'bread', 'cactus', 'carrot', 'cedar', 'cherry', 'cocoa', 'corn', 'cress', 'daisy', 'date',
  'fern', 'fig', 'garlic', 'ginger', 'grape', 'hazel', 'herb', 'honey', 'ivy', 'kale',
  'leaf', 'lemon', 'lentil', 'lilac', 'lime', 'lotus', 'maize', 'mango', 'maple', 'melon',
  'mint', 'moss', 'nutmeg', 'oak', 'oat', 'olive', 'onion', 'orange', 'palm', 'papaya',
  'peach', 'pear', 'pecan', 'pepper', 'pine', 'plum', 'poppy', 'potato', 'radish', 'rice',
  'rose', 'sage', 'salt', 'spruce', 'sugar', 'thyme', 'tomato', 'tulip', 'walnut', 'wheat',
  'willow', 'yeast',

  // landscape and weather
  'atoll', 'bay', 'beach', 'bluff', 'brook', 'canyon', 'cave', 'cliff', 'cloud', 'coast',
  'comet', 'creek', 'delta', 'desert', 'dew', 'dune', 'dusk', 'earth', 'fjord', 'fog',
  'forest', 'frost', 'geyser', 'glade', 'glen', 'gorge', 'grotto', 'grove', 'gulf', 'hail',
  'harbor', 'hill', 'island', 'jungle', 'lagoon', 'lake', 'marsh', 'meadow', 'mesa', 'mist',
  'moon', 'oasis', 'ocean', 'peak', 'plain', 'pond', 'rain', 'reef', 'ridge', 'river',
  'sand', 'shore', 'sky', 'sleet', 'snow', 'star', 'storm', 'stream', 'summit', 'sun',
  'swamp', 'thunder', 'tide', 'tundra', 'valley', 'volcano', 'wind',

  // colors and qualities
  'amber', 'azure', 'beige', 'black', 'blue', 'bold', 'brave', 'brief', 'bright', 'bronze',
  'brown', 'calm', 'clean', 'clear', 'cold', 'cool', 'copper', 'coral', 'crimson', 'crisp',
  'dark', 'deep', 'dry', 'empty', 'fair', 'fast', 'firm', 'flat', 'fresh', 'full',
  'gentle', 'glad', 'golden', 'gray', 'green', 'happy', 'hard', 'high', 'hollow', 'honest',
  'humble', 'indigo', 'ivory', 'jade', 'keen', 'kind', 'large', 'light', 'long', 'loud',
  'low', 'mauve', 'mellow', 'mild', 'narrow', 'neat', 'noble', 'olive', 'open', 'pale',
  'pink', 'plain', 'proud', 'purple', 'quick', 'quiet', 'rapid', 'red', 'rich', 'ripe',
  'rough', 'round', 'royal', 'rustic', 'scarlet', 'sharp', 'short', 'silent', 'silver', 'simple',
  'slow', 'small', 'smooth', 'soft', 'solid', 'sour', 'steady', 'stern', 'still', 'strong',
  'sweet', 'swift', 'tall', 'tan', 'teal', 'tender', 'thick', 'thin', 'tidy', 'tiny',
  'violet', 'warm', 'white', 'wide', 'wise', 'yellow', 'young',

  // objects and tools
  'anchor', 'anvil', 'arrow', 'axe', 'badge', 'barrel', 'basket', 'beacon', 'bell', 'belt',
  'bench', 'blanket', 'boat', 'bolt', 'book', 'boot', 'bottle', 'bowl', 'box', 'brick',
  'bridge', 'broom', 'brush', 'bucket', 'cabin', 'cable', 'camera', 'candle', 'canoe', 'canvas',
  'carpet', 'cart', 'chain', 'chair', 'chest', 'chisel', 'clock', 'coin', 'collar', 'comb',
  'compass', 'cord', 'crate', 'crown', 'cup', 'curtain', 'dagger', 'desk', 'dial', 'dish',
  'door', 'drum', 'engine', 'fan', 'fence', 'file', 'flag', 'flask', 'flute', 'fork',
  'frame', 'funnel', 'gate', 'gear', 'glass', 'globe', 'glove', 'hammer', 'handle', 'harp',
  'hat', 'helmet', 'hinge', 'hook', 'jar', 'kettle', 'key', 'kite', 'knob', 'ladder',
  'lamp', 'lantern', 'latch', 'ledger', 'lens', 'lever', 'lock', 'magnet', 'mallet', 'map',
  'mask', 'mast', 'mirror', 'nail', 'needle', 'net', 'oar', 'organ', 'paddle', 'pail',
  'panel', 'paper', 'pencil', 'piano', 'pillar', 'pin', 'pipe', 'pistol', 'piston', 'plank',
  'plate', 'pliers', 'plow', 'pocket', 'pot', 'pulley', 'pump', 'purse', 'quill', 'quilt',
  'radio', 'raft', 'rake', 'ribbon', 'ring', 'rivet', 'rope', 'rudder', 'ruler', 'saddle',
  'sail', 'scale', 'screw', 'shovel', 'sickle', 'sieve', 'signal', 'skate', 'sled', 'socket',
  'spade', 'spoon', 'spring', 'stamp', 'statue', 'stove', 'string', 'switch', 'table', 'tank',
  'tent', 'thread', 'ticket', 'tile', 'timber', 'tongs', 'tool', 'torch', 'towel', 'tower',
  'trowel', 'trumpet', 'tunnel', 'valve', 'vase', 'vault', 'violin', 'wagon', 'wallet', 'watch',
  'wedge', 'well', 'wheel', 'whistle', 'window', 'wire', 'wrench', 'yarn',

  // places and structures
  'abbey', 'arcade', 'arch', 'arena', 'attic', 'barn', 'bazaar', 'bunker', 'castle', 'cellar',
  'chapel', 'citadel', 'city', 'cottage', 'court', 'dock', 'dome', 'farm', 'forge', 'fort',
  'garden', 'hangar', 'haven', 'hostel', 'kiosk', 'lodge', 'manor', 'market', 'mill', 'museum',
  'palace', 'park', 'pier', 'plaza', 'port', 'quarry', 'ranch', 'road', 'school', 'shed',
  'stable', 'studio', 'temple', 'theater', 'tomb', 'town', 'tunnel', 'village', 'wharf',

  // abstract but concrete-sounding
  'answer', 'anthem', 'ballad', 'banner', 'cipher', 'cobalt', 'custom', 'echo', 'ember', 'emblem',
  'fable', 'flame', 'gambit', 'granite', 'hazard', 'legend', 'marble', 'matrix', 'method', 'motto',
  'myth', 'nickel', 'omen', 'opal', 'orbit', 'order', 'pattern', 'pearl', 'pewter', 'poem',
  'prism', 'proverb', 'puzzle', 'quartz', 'quest', 'relic', 'rhythm', 'riddle', 'rune', 'saga',
  'script', 'shadow', 'signal', 'sonnet', 'spark', 'sphere', 'spiral', 'symbol', 'tactic', 'talon',
  'theme', 'token', 'topaz', 'totem', 'trophy', 'verse', 'vertex', 'vigil', 'wisdom', 'zenith',
];

/** Do two words differ by exactly one letter (substitution, insertion or deletion)? */
function differsByOneLetter(a, b) {
  if (Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    let diff = 0;
    for (let i = 0; i < a.length; i += 1) {
      if (a[i] !== b[i]) diff += 1;
      if (diff > 1) return false;
    }
    return diff === 1;
  }
  const [shorter, longer] = a.length < b.length ? [a, b] : [b, a];
  for (let i = 0; i < longer.length; i += 1) {
    if (longer.slice(0, i) + longer.slice(i + 1) === shorter) return true;
  }
  return false;
}

/**
 * Build the published list.
 *
 * Duplicates across themed groups are easy to introduce by hand — `coral`, `olive`, `plain`,
 * `signal` and `tunnel` each legitimately fit two categories — and a duplicate would skew the
 * entropy calculation, so they go first. Then shape, then the one-letter rule.
 *
 * Longer words are preferred when a pair collides: they carry more distinguishing sound, which is
 * what matters for a code read down a phone line.
 */
function build() {
  const unique = [...new Set(WORDS)];
  const shaped = unique.filter((word) => /^[a-z]{3,7}$/.test(word));
  const malformed = unique.filter((word) => !/^[a-z]{3,7}$/.test(word));

  const candidates = [...shaped].sort((a, b) => b.length - a.length || a.localeCompare(b));
  const kept = [];
  const collided = [];
  for (const word of candidates) {
    const clash = kept.find((existing) => differsByOneLetter(word, existing));
    if (clash) collided.push(`${word} (clashes with ${clash})`);
    else kept.push(word);
  }

  return {
    list: Object.freeze(kept.sort()),
    dropped: Object.freeze({
      duplicates: WORDS.length - unique.length,
      malformed: Object.freeze(malformed),
      collided: Object.freeze(collided.sort()),
    }),
    sourceCount: WORDS.length,
  };
}

const built = build();

/** The published, collision-free wordlist. 506 words at the time of writing; measure, don't trust. */
const WORDLIST = built.list;

/** What the filter removed, so a word that silently vanished can be found. */
const DROPPED = built.dropped;

const SOURCE_COUNT = built.sourceCount;

module.exports = { DROPPED, SOURCE_COUNT, WORDLIST, differsByOneLetter };
