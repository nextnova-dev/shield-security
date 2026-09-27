<?php
/**
 * NovaShield AI Threat Verification
 *
 * Sends flagged code snippets to the Claude API to confirm whether
 * a heuristic hit is genuine malware or a false positive.
 * Only heuristic threats go through verification — known-signature
 * threats (interseq.at, wordpress-defender etc.) are confirmed by
 * definition and skip this step.
 *
 * Requires: Anthropic API key entered in Shield Security → Settings.
 */
if ( ! defined( 'ABSPATH' ) ) exit;

class Shield_AI_Verify {

    const API_URL    = 'https://api.anthropic.com/v1/messages';
    const API_MODEL  = 'claude-sonnet-4-6';
    const MAX_TOKENS = 256;   // verdict only — short response
    const TIMEOUT    = 20;    // seconds

    // How many lines of context to send either side of the flagged line
    const CONTEXT_LINES = 8;

    // Maximum characters of code to send (keeps cost low)
    const MAX_CODE_CHARS = 2000;

    // ── Public API ────────────────────────────────────────────────────

    /**
     * Verify a batch of heuristic threats.
     * Returns the same array with each threat updated:
     *   - 'ai_verdict'    => 'malicious' | 'clean' | 'uncertain'
     *   - 'ai_confidence' => 'high' | 'medium' | 'low'
     *   - 'ai_reason'     => short explanation string
     *   - 'verified'      => true
     * Threats without a file (DB, cron, user) are returned unchanged.
     */
    public static function verify_batch( array $threats ) {
        $api_key = self::get_api_key();
        if ( ! $api_key ) {
            // No key configured — mark all as unverified and return
            foreach ( $threats as &$t ) {
                $t['ai_verdict']  = 'unverified';
                $t['ai_reason']   = 'No API key configured. Go to Shield Security → Settings → AI Verification.';
            }
            return $threats;
        }

        foreach ( $threats as &$threat ) {
            // Only verify heuristic hits — signature hits are definitive
            if ( ( $threat['type'] ?? '' ) !== 'heuristic' ) {
                $threat['verified'] = false;
                continue;
            }
            $result = self::verify_single( $threat, $api_key );
            $threat = array_merge( $threat, $result );
        }
        unset( $threat );
        return $threats;
    }

    /**
     * Check if AI verification is enabled and configured.
     */
    public static function is_enabled() {
        return ! empty( self::get_api_key() );
    }

    public static function get_api_key() {
        $settings = shield_get_settings();
        return ! empty( $settings['anthropic_api_key'] )
            ? trim( $settings['anthropic_api_key'] )
            : '';
    }

    // ── Core verification ─────────────────────────────────────────────

    private static function verify_single( array $threat, $api_key ) {
        $file = $threat['file'] ?? '';
        if ( ! $file || ! file_exists( $file ) ) {
            return array(
                'ai_verdict'  => 'uncertain',
                'ai_reason'   => 'File not found for verification.',
                'verified'    => true,
            );
        }

        $snippet = self::extract_snippet( $file, $threat['description'] ?? '' );
        if ( ! $snippet ) {
            return array(
                'ai_verdict'  => 'uncertain',
                'ai_reason'   => 'Could not read file for verification.',
                'verified'    => true,
            );
        }

        $prompt = self::build_prompt( $threat, $snippet );
        $response = self::call_api( $prompt, $api_key );

        if ( is_wp_error( $response ) ) {
            return array(
                'ai_verdict'  => 'uncertain',
                'ai_reason'   => 'AI verification failed: ' . $response->get_error_message(),
                'verified'    => true,
            );
        }

        return self::parse_response( $response );
    }

    // ── Code extraction ───────────────────────────────────────────────

    /**
     * Extract the relevant snippet from the file.
     * Finds the line(s) matching the flagged pattern and returns
     * those lines plus CONTEXT_LINES either side.
     */
    private static function extract_snippet( $file_path, $description ) {
        $content = @file_get_contents( $file_path );
        if ( ! $content ) return '';

        // Truncate very large files early
        if ( strlen( $content ) > 100000 ) {
            $content = substr( $content, 0, 100000 );
        }

        $lines       = explode( "\n", $content );
        $total_lines = count( $lines );
        $hit_line    = null;

        // Find the line that contains the suspicious pattern
        // Use keywords from the description to locate it
        $keywords = self::description_to_keywords( $description );
        foreach ( $lines as $i => $line ) {
            foreach ( $keywords as $kw ) {
                if ( stripos( $line, $kw ) !== false ) {
                    $hit_line = $i;
                    break 2;
                }
            }
        }

        // If we couldn't find a specific line, send the first 60 lines
        if ( $hit_line === null ) {
            $snippet_lines = array_slice( $lines, 0, 60 );
        } else {
            $from = max( 0, $hit_line - self::CONTEXT_LINES );
            $to   = min( $total_lines - 1, $hit_line + self::CONTEXT_LINES );
            $snippet_lines = array_slice( $lines, $from, $to - $from + 1, true );
        }

        // Add line numbers
        $numbered = array();
        foreach ( $snippet_lines as $num => $line ) {
            $numbered[] = ( $num + 1 ) . ': ' . $line;
        }
        $snippet = implode( "\n", $numbered );

        // Truncate to cost limit
        if ( strlen( $snippet ) > self::MAX_CODE_CHARS ) {
            $snippet = substr( $snippet, 0, self::MAX_CODE_CHARS ) . "\n... [truncated]";
        }

        return $snippet;
    }

    private static function description_to_keywords( $description ) {
        // Map heuristic description strings to code keywords to search for
        $map = array(
            'char-by-char'     => array( 'chr(', '. chr(' ),
            'XOR-encoded'      => array( 'chr(', 'array_map', 'implode' ),
            'large base64'     => array( 'base64_decode', 'base64' ),
            'eval+base64'      => array( 'eval', 'base64_decode' ),
            'eval+gzinflate'   => array( 'eval', 'gzinflate' ),
            'preg_replace /e'  => array( 'preg_replace', '/e' ),
            'wp_footer'        => array( 'wp_footer', 'add_action' ),
            'fromCharCode'     => array( 'fromCharCode', 'String.' ),
            'gzinflate+base64' => array( 'gzinflate', 'base64' ),
        );
        foreach ( $map as $key => $keywords ) {
            if ( stripos( $description, $key ) !== false ) return $keywords;
        }
        // Default: use words from description
        $words = preg_split( '/\s+/', $description );
        return array_filter( $words, function( $w ) { return strlen( $w ) > 4; } );
    }

    // ── Prompt ────────────────────────────────────────────────────────

    private static function build_prompt( array $threat, $snippet ) {
        $location    = $threat['location']    ?? 'unknown';
        $description = $threat['description'] ?? 'suspicious pattern';
        $rel_path    = $threat['location']    ?? '';

        return "You are a WordPress malware analyst. A security scanner flagged this PHP file as suspicious.\n\n" .
               "File: {$location}\n" .
               "Scanner flagged: {$description}\n\n" .
               "Code snippet (with line numbers):\n" .
               "```php\n{$snippet}\n```\n\n" .
               "Analyse this code carefully. Determine if it is:\n" .
               "1. MALICIOUS — genuinely harmful code (webshell, credential harvester, C2 beacon, obfuscated payload, backdoor)\n" .
               "2. CLEAN — legitimate code from a known plugin/library/theme that happens to use patterns that look suspicious (e.g. chr() arrays for character validation, base64 for data encoding, eval in template engines)\n" .
               "3. UNCERTAIN — ambiguous, cannot determine without more context\n\n" .
               "Consider the file path carefully — vendor/, vendor_prefixed/, src/Libs/, and phpseclib paths are almost always legitimate.\n\n" .
               "Reply ONLY with a JSON object, no other text:\n" .
               "{\"verdict\":\"malicious|clean|uncertain\",\"confidence\":\"high|medium|low\",\"reason\":\"one sentence explanation\"}";
    }

    // ── API call ──────────────────────────────────────────────────────

    private static function call_api( $prompt, $api_key ) {
        $body = wp_json_encode( array(
            'model'      => self::API_MODEL,
            'max_tokens' => self::MAX_TOKENS,
            'messages'   => array(
                array( 'role' => 'user', 'content' => $prompt ),
            ),
        ) );

        $response = wp_remote_post( self::API_URL, array(
            'timeout' => self::TIMEOUT,
            'headers' => array(
                'Content-Type'      => 'application/json',
                'x-api-key'         => $api_key,
                'anthropic-version' => '2023-06-01',
            ),
            'body' => $body,
        ) );

        if ( is_wp_error( $response ) ) return $response;

        $code = wp_remote_retrieve_response_code( $response );
        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( $code === 401 ) {
            return new WP_Error( 'auth', 'Invalid API key. Check Shield Security → Settings → AI Verification.' );
        }
        if ( $code === 429 ) {
            return new WP_Error( 'rate_limit', 'API rate limit reached. Try again in a moment.' );
        }
        if ( $code !== 200 || empty( $data['content'][0]['text'] ) ) {
            return new WP_Error( 'api_error', 'Unexpected API response (HTTP ' . $code . ').' );
        }

        return $data['content'][0]['text'];
    }

    // ── Response parsing ──────────────────────────────────────────────

    private static function parse_response( $text ) {
        // Strip any markdown fences just in case
        $text  = preg_replace( '/```json?\s*|\s*```/', '', trim( $text ) );
        $data  = json_decode( $text, true );

        $verdict    = $data['verdict']    ?? 'uncertain';
        $confidence = $data['confidence'] ?? 'low';
        $reason     = $data['reason']     ?? 'No reason provided.';

        // Normalise verdict
        if ( ! in_array( $verdict, array( 'malicious', 'clean', 'uncertain' ), true ) ) {
            $verdict = 'uncertain';
        }

        return array(
            'ai_verdict'    => $verdict,
            'ai_confidence' => $confidence,
            'ai_reason'     => sanitize_text_field( $reason ),
            'verified'      => true,
        );
    }

    // ── Settings helpers ──────────────────────────────────────────────

    /**
     * Mask API key for display — show only last 6 characters.
     */
    public static function mask_key( $key ) {
        if ( strlen( $key ) < 10 ) return str_repeat( '•', strlen( $key ) );
        return str_repeat( '•', strlen( $key ) - 6 ) . substr( $key, -6 );
    }

    /**
     * Validate an Anthropic API key format (starts with sk-ant-).
     */
    public static function validate_key_format( $key ) {
        return ( strpos( $key, 'sk-ant-' ) === 0 && strlen( $key ) > 20 );
    }
}
