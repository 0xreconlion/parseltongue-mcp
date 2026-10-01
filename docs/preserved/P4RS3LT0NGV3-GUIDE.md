# 🐍 P4RS3LT0NGV3

## Speak beyond plain text.

**P4RS3LT0NGV3** ("Parseltongue") is a browser-based text laboratory for transforming, translating, inspecting, encoding, and decoding text. It brings hundreds of writing systems, ciphers, encodings, Unicode styles, and research utilities into one focused workspace—so a message can be made readable, stylized, represented differently, or investigated without bouncing among single-purpose tools.

It is designed for curious writers, educators, puzzle makers, language enthusiasts, security researchers, and anyone working with text that does not arrive in plain English.

> **The idea:** text has more than one form. Parseltongue lets you explore the space between what a message says and how it is represented.

## What it does

P4RS3LT0NGV3 contains **222 built-in transforms**, grouped into practical families:

| Need | What Parseltongue offers |
| --- | --- |
| Change how text looks | Case changes, Unicode styles, spacing, symbol alphabets, runes, scripts, and decorative text |
| Encode or decode data | Base64, hex, binary, URL encoding, QR/barcode workflows, and many other common representations |
| Explore ciphers | Caesar, Vigenère, Playfair, rail fence, Polybius, ROT variants, and other classical cipher families |
| Read unfamiliar text | A universal decoder that detects supported formats and supplies script and language hints |
| Translate language | AI-powered translation through an optional OpenRouter connection, including historical and specialist languages |
| Hide a message in a carrier | Emoji, zero-width, whitespace, Unicode Tags, acrostic, and other steganography experiments |
| Create variations | Mutation Lab, gibberish, tokenization, splitting, spelling alphabets, and custom character mappings |

It is not one encryption product or one AI prompt tool. It is a flexible **text transformation workbench**: pick the representation that fits the task, inspect the result, and reverse it when the selected method supports decoding.

## Start here

1. Build and open the app:

   ```bash
   npm install
   npm run build
   ```

2. Open `dist/index.html` in a modern browser. For a bookmarkable local address, run `npm start` and open `http://localhost:8080`.

3. Enter text in the active tool, choose a transform or workflow, then copy or download the result.

Most transforms run entirely in the browser. AI features require an OpenRouter API key; see [Using AI features](#using-ai-features) below.

## The everyday workflow

### 1. Transform text

Open **Transform** (`T`), type or paste your text, and select a card. Categories make it easy to narrow the field: Cipher, Encoding, Unicode, Symbol, Technical, Format, Visual, and more.

Use the gear icon on a transform card when it offers settings—for example, a Caesar shift or a Vigenère key. Favorite frequently used transforms to keep them close, and use recent selections to continue a workflow.

**Example:** select **Caesar Cipher**, set the shift to `5`, and transform `Attack at dawn`. Choose the same transform’s reverse path later to recover the original text.

### 2. Decode an unknown representation

Open **Decoder** or navigate to `#decoder`. Paste the text and let Parseltongue try its supported detectors and reverse transforms. Results are ranked, and alternative plausible readings are retained when available.

The decoder is a strong first pass, not a guarantee. It works best for supported encodings and recognizable transform signatures. For a keyed cipher or ambiguous text, you still need the key or contextual knowledge.

### 3. Turn text into a code—or read one

Open **Codes** (`#codes`) to generate a QR code, Code 128, EAN-13, or Code 39 barcode. Use `#codes/decode` to scan an uploaded QR or barcode image. Decoding happens client-side, so the uploaded image remains in the browser.

### 4. Explore a message as a payload

Use **Emoji** (`H`) to experiment with emoji carriers and invisible Unicode representations. **Tokenade**, **Mutation Lab**, **Bijection**, **Splitter**, and **Tokenizer** are for examining how a message changes under different structures, chunking rules, tokenization schemes, and character mappings.

These tools are especially useful for puzzle design, robustness testing, teaching, and text-format research.

## A quick guide to the toolset

### Transform

The main studio. Apply, reverse, preview, favorite, and configure the project’s 222 transforms. This is the right place to begin when you know the technique you want.

### Decoder

The discovery tool. Paste an unfamiliar string and let Parseltongue identify supported encodings or transformations. It can also provide Unicode-script and language clues.

### Emoji

The steganography studio. Encode and recover short messages with compatible emoji carriers or invisible Unicode text. Advanced Settings controls the underlying variation-selector and bit-order choices.

### Codes

The visual-code utility. Create QR codes and common one-dimensional barcodes, or decode a supported image locally.

### Tokenizer and Splitter

The text-structure utilities. Tokenizer compares UTF-8 bytes, words, and several GPT BPE tokenizers. Splitter breaks content by size, words, sentences, lines, regex, or token count, with optional transform chains.

### Mutation Lab, Gibberish, and Bijection

The variation tools. Generate repeatable or randomized variants, remove or alter characters, and build custom character-to-value mappings for experiments or games.

### Spelling Alphabets

Create and save your own A–Z phonetic alphabets. Build one manually, or use an optional AI-assisted first draft, then edit every entry before saving. Saved alphabets become transforms in the main studio.

### PromptCraft and Anti-Classifier

Optional AI-assisted writing tools powered by OpenRouter. PromptCraft produces controlled variants using strategies such as rephrasing, expansion, compression, metaphor, or custom instructions. Anti-Classifier focuses on syntactic and paraphrase-style rewrites for research prompts. Review every output before use; they are generative aids, not sources of fact or guarantees of policy compliance.

## Using AI features

AI Translation, PromptCraft, Anti-Classifier, optional Decoder translation, and AI-assisted Spelling Alphabet generation connect through **OpenRouter**.

1. Create an OpenRouter account and API key.
2. In Parseltongue, open **Advanced Settings**—in the desktop utility dock, or via the columns icon on a narrow screen.
3. Paste the key, select **Save Key**, then choose the models you want shown in the relevant tools.

The key is stored in that browser’s local storage and is sent only to OpenRouter when an AI request is made. Core transforms, decoding, emoji work, and QR/barcode work do not need the key or a cloud connection.

## What “Parseltongue” means here

The name is a playful metaphor for making sense of unfamiliar language. In this product, it means moving fluently between text representations:

```text
Plain language → representation → inspection / recovery → understanding
```

Sometimes that representation is a conventional encoding such as Base64. Sometimes it is a historical alphabet, a visual code, a cipher, a Unicode style, or a hidden-data carrier. Parseltongue helps make the conversion visible and reversible where the technique permits it.

## Privacy and responsible use

- **Local by default:** the static app’s core transform, decoder, and code workflows run in your browser.
- **AI is opt-in:** only AI-enabled features send text to OpenRouter.
- **Encoding is not encryption:** Base64, Unicode styling, steganography, and most classical ciphers should not be treated as protection for sensitive data. Use modern, vetted encryption when confidentiality matters.
- **Use with consent:** do not use concealment, mutation, or code-generation features to evade platform rules, impersonate others, or mislead people.

## Keyboard and navigation shortcuts

| Shortcut or link | Action |
| --- | --- |
| `T` | Open Transform |
| `H` | Open Emoji / steganography |
| `D` | Cycle visual themes |
| `#decoder` | Open Decoder directly |
| `#steganography` | Open Emoji / steganography directly |
| `#codes` | Open code generator directly |
| `#codes/decode` | Open code scanner directly |

## For command-line and agent workflows

The repository also includes a Python CLI that uses the same canonical transform runtime as the web app.

```bash
uv run p4rs3lt0ngv3-cli list
uv run p4rs3lt0ngv3-cli inspect caesar --json
uv run p4rs3lt0ngv3-cli encode --transform base64 --text "Hello World"
uv run p4rs3lt0ngv3-cli auto-decode --text "SGVsbG8="
uv run p4rs3lt0ngv3-cli agent "encode 'Hello' as caesar shift 5"
```

Use `list` to discover transforms, `inspect` to see supported options, and `encode`, `decode`, or `preview` for deterministic operations. The `agent` command accepts a concise natural-language request and resolves it into the applicable workflow.

---

**P4RS3LT0NGV3 4.0**  
*A universal text translator for the messages that refuse to stay plain.*
