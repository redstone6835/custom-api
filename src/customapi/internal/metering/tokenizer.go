// Package metering implements the gateway's independent view of token usage.
//
// The customs gateway never trusts an upstream's reported usage. For every
// exchange it computes its own estimate from the request and response bodies
// and compares the two; a deviation beyond a configured tolerance is an audit
// event (see counter.go) and feeds channel de-weighting.
//
// # Estimator design
//
// The gateway is deliberately dependency-free and therefore cannot embed every
// vendor BPE vocabulary. Instead it classifies text into tokenizer-relevant
// segments (CJK, Latin words, digits, punctuation, whitespace, code) and
// applies per-segment byte/character ratios calibrated against tiktoken
// o200k/cl100k and the Anthropic tokenizer. This yields a bounded relative
// error that is far smaller than the deviations a dishonest upstream would
// need to produce to profit, which is what the check is for.
package metering

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// TokenizerFamily identifies the tokenizer behaviour a model family uses.
type TokenizerFamily string

const (
	// FamilyCl100k approximates the OpenAI cl100k_base tokenizer
	// (gpt-4, gpt-3.5, text-embedding-3-*).
	FamilyCl100k TokenizerFamily = "cl100k"
	// FamilyO200k approximates the OpenAI o200k_base tokenizer
	// (gpt-4o, gpt-4.1, o-series).
	FamilyO200k TokenizerFamily = "o200k"
	// FamilyClaude approximates the Anthropic Claude tokenizer.
	FamilyClaude TokenizerFamily = "claude"
	// FamilyGemini approximates the Google SentencePiece tokenizer.
	FamilyGemini TokenizerFamily = "gemini"
	// FamilyGeneric is the fallback for unknown models.
	FamilyGeneric TokenizerFamily = "generic"
)

// SentencePieceDelimiter identifies families that encode a leading space as
// part of the token (Gemini and other SentencePiece models).
func (f TokenizerFamily) SentencePieceDelimiter() bool { return f == FamilyGemini }

// cjkRatio is the tokens-per-CJK-character ratio. CJK text is roughly one
// token per character for the modern OpenAI/Anthropic vocabularies.
const cjkRatio = 1.0

// FamilyFor maps a model identifier to a tokenizer family.
func FamilyFor(model string) TokenizerFamily {
	m := strings.ToLower(model)
	switch {
	case strings.Contains(m, "claude"):
		return FamilyClaude
	case strings.Contains(m, "gemini"), strings.Contains(m, "gemma"), strings.Contains(m, "palm"):
		return FamilyGemini
	case strings.Contains(m, "o200k"), strings.Contains(m, "gpt-4o"),
		strings.Contains(m, "gpt-4.1"), strings.Contains(m, "gpt-5"),
		strings.Contains(m, "chatgpt-4o"):
		return FamilyO200k
	case strings.Contains(m, "o1"), strings.Contains(m, "o3"), strings.Contains(m, "o4"):
		return FamilyO200k
	case strings.Contains(m, "gpt-4"), strings.Contains(m, "gpt-3.5"),
		strings.Contains(m, "text-embedding"), strings.Contains(m, "davinci"):
		return FamilyCl100k
	case strings.Contains(m, "qwen"), strings.Contains(m, "glm"),
		strings.Contains(m, "deepseek"), strings.Contains(m, "kimi"),
		strings.Contains(m, "moonshot"), strings.Contains(m, "yi-"),
		strings.Contains(m, "baichuan"), strings.Contains(m, "ernie"),
		strings.Contains(m, "doubao"), strings.Contains(m, "hunyuan"),
		strings.Contains(m, "minimax"), strings.Contains(m, "step-"):
		// Chinese vendors ship SentencePiece/BPE hybrids; the CJK-heavy
		// behaviour dominates and matches the generic ratios.
		return FamilyGeneric
	default:
		return FamilyGeneric
	}
}

// familyRatios holds tokens-per-byte for ASCII-ish scripts and an extra
// penalty for digit runs, per family.
type familyRatios struct {
	ascii    float64 // tokens per byte for ordinary Latin text
	digits   float64 // tokens per byte for digit runs
	punct    float64 // tokens per byte for punctuation/symbols
	newline  float64 // tokens per newline run
	cjkScale float64 // multiplier applied to cjkRatio
}

func ratiosFor(f TokenizerFamily) familyRatios {
	switch f {
	case FamilyCl100k:
		return familyRatios{ascii: 0.255, digits: 0.36, punct: 0.40, newline: 0.5, cjkScale: 1.35}
	case FamilyO200k:
		return familyRatios{ascii: 0.215, digits: 0.33, punct: 0.36, newline: 0.5, cjkScale: 1.00}
	case FamilyClaude:
		return familyRatios{ascii: 0.220, digits: 0.34, punct: 0.38, newline: 0.5, cjkScale: 1.15}
	case FamilyGemini:
		return familyRatios{ascii: 0.240, digits: 0.35, punct: 0.39, newline: 0.5, cjkScale: 1.05}
	default:
		return familyRatios{ascii: 0.240, digits: 0.35, punct: 0.38, newline: 0.5, cjkScale: 1.05}
	}
}

// Estimator counts tokens for one tokenizer family.
type Estimator struct {
	Family TokenizerFamily
	r      familyRatios
}

// NewEstimator returns an estimator for an explicit family.
func NewEstimator(f TokenizerFamily) *Estimator {
	return &Estimator{Family: f, r: ratiosFor(f)}
}

// NewEstimatorForModel returns an estimator chosen from a model identifier.
func NewEstimatorForModel(model string) *Estimator { return NewEstimator(FamilyFor(model)) }

// textClass labels a run of same-class runes.
type textClass int

const (
	classLatin textClass = iota
	classCJK
	classDigits
	classPunct
	classSpace
)

func classify(r rune) textClass {
	switch {
	case r == ' ' || r == '\t' || r == '\n' || r == '\r':
		return classSpace
	case unicode.Is(unicode.Han, r) || unicode.Is(unicode.Hiragana, r) ||
		unicode.Is(unicode.Katakana, r) || unicode.Is(unicode.Hangul, r):
		return classCJK
	case r >= '0' && r <= '9':
		return classDigits
	case unicode.IsLetter(r), unicode.IsMark(r):
		return classLatin
	default:
		return classPunct
	}
}

// Estimate returns the estimated token count for a piece of text.
//
// The return value is always at least 1 for non-empty input, mirroring the
// behaviour of real tokenizers which emit at least one token for any content.
func (e *Estimator) Estimate(text string) int {
	if text == "" {
		return 0
	}
	if e == nil {
		e = NewEstimator(FamilyGeneric)
	}
	var (
		tokens   float64
		runBytes int
		curClass = classifyFirst(text)
		flush    = func() {
			if runBytes == 0 {
				return
			}
			n := float64(runBytes)
			switch curClass {
			case classLatin:
				tokens += n * e.r.ascii
			case classDigits:
				tokens += n * e.r.digits
			case classPunct:
				tokens += n * e.r.punct
			case classSpace:
				tokens += n * e.r.newline
			case classCJK:
				tokens += n * e.r.cjkScale * cjkRatio / 3.0 // 3 bytes per CJK char
			}
			runBytes = 0
		}
	)
	for _, r := range text {
		c := classify(r)
		if c != curClass {
			flush()
			curClass = c
		}
		runBytes += utf8.RuneLen(r)
	}
	flush()

	// Word-boundary correction.
	//
	// For long text the per-byte ratio is accurate because the average token
	// length converges. For short text it is not: real BPE vocabularies
	// contain whole common words (" instructions", " the"), so the true count
	// tracks the number of space-separated words more closely than the byte
	// count does. Blending the two removes a systematic bias that would
	// otherwise show up as a false usage-integrity signal on short prompts.
	if words := countWords(text); words >= minWordsForCorrection {
		if wordEstimate := float64(words) * e.wordsPerToken(); wordEstimate < tokens {
			tokens = 0.5*tokens + 0.5*wordEstimate
		}
	}

	n := int(tokens + 0.5)
	if n < 1 {
		n = 1
	}
	return n
}

// minWordsForCorrection is the shortest text for which the word-boundary blend
// is applied. Below it the estimate is dominated by a handful of tokens and
// blending would add noise rather than remove bias.
const minWordsForCorrection = 3

// wordsPerToken is the mean number of space-separated words encoded by one
// token in ordinary prose, per family. It is the reciprocal of the average
// token length in words.
func (e *Estimator) wordsPerToken() float64 {
	switch e.Family {
	case FamilyO200k:
		return 1.30
	case FamilyCl100k:
		return 1.10
	case FamilyClaude:
		return 1.20
	case FamilyGemini:
		return 1.15
	default:
		return 1.15
	}
}

// countWords counts space-separated words, treating punctuation-only runs as
// non-words.
func countWords(text string) int {
	n := 0
	inWord := false
	for _, r := range text {
		if unicode.IsSpace(r) {
			inWord = false
			continue
		}
		if !inWord {
			n++
			inWord = true
		}
	}
	return n
}

func classifyFirst(s string) textClass {
	r, _ := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError {
		return classLatin
	}
	return classify(r)
}

// EstimateBytes estimates tokens for raw bytes (used for streamed deltas).
func (e *Estimator) EstimateBytes(b []byte) int { return e.Estimate(string(b)) }
