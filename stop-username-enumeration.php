<?php
/**
 * Plugin Name: Stop Username Enumeration
 * Description: Blocks common WordPress username enumeration vectors: ?author= queries, REST API user endpoints, login error hints, and XML-RPC. Activate and forget.
 * Version: 1.0.0
 * Author: Fergell Murphy
 */

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Stop_Username_Enumeration {

    public function __construct() {
        // 1. Block ?author=N enumeration via query string
        add_action( 'init', array( $this, 'block_author_query_enum' ) );

        // 2. Block author archive pages entirely by redirecting to home
        add_action( 'template_redirect', array( $this, 'block_author_archives' ) );

        // 3. Remove/limit REST API user endpoints for unauthenticated requests
        add_filter( 'rest_endpoints', array( $this, 'restrict_rest_user_endpoints' ) );

        // 4. Generic login error message (no "invalid username" vs "incorrect password" hints)
        add_filter( 'login_errors', array( $this, 'generic_login_error' ) );

        // 5. Disable XML-RPC (also helps prevent brute-force + enumeration via pingback)
        add_filter( 'xmlrpc_enabled', '__return_false' );

        // 6. Remove REST API user data from oEmbed / other exposed areas
        add_filter( 'rest_prepare_user', array( $this, 'strip_user_rest_data' ), 10, 3 );

        // 7. Block user enumeration via sitemaps (WP core sitemaps expose author archives)
        add_filter( 'wp_sitemaps_add_provider', array( $this, 'remove_author_sitemap' ), 10, 2 );
    }

    /**
     * Block requests like /?author=1 from resolving to an author archive.
     */
    public function block_author_query_enum() {
        if ( is_admin() ) {
            return;
        }

        if ( isset( $_REQUEST['author'] ) && $_REQUEST['author'] !== '' ) {
            wp_safe_redirect( home_url(), 301 );
            exit;
        }
    }

    /**
     * Block direct access to author archive pages (/author/username/).
     */
    public function block_author_archives() {
        if ( is_author() ) {
            wp_safe_redirect( home_url(), 301 );
            exit;
        }
    }

    /**
     * Remove the /wp/v2/users endpoints for unauthenticated users.
     * Logged-in admins/editors can still use them if needed.
     */
    public function restrict_rest_user_endpoints( $endpoints ) {
        if ( is_user_logged_in() ) {
            return $endpoints;
        }

        if ( isset( $endpoints['/wp/v2/users'] ) ) {
            unset( $endpoints['/wp/v2/users'] );
        }
        if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
            unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
        }

        return $endpoints;
    }

    /**
     * Extra safety net: strip sensitive fields if a user-related REST response
     * still slips through (e.g. via a plugin re-adding the endpoint).
     */
    public function strip_user_rest_data( $response, $user, $request ) {
        if ( is_user_logged_in() ) {
            return $response;
        }

        $data = $response->get_data();
        unset( $data['slug'], $data['name'] );
        $response->set_data( $data );

        return $response;
    }

    /**
     * Generic login error so failed logins don't confirm whether a username exists.
     */
    public function generic_login_error() {
        return __( 'Invalid login credentials.', 'stop-username-enumeration' );
    }

    /**
     * Remove the "users" provider from WP core XML sitemaps (exposes author archive URLs).
     */
    public function remove_author_sitemap( $provider, $name ) {
        if ( 'users' === $name ) {
            return false;
        }
        return $provider;
    }
}

new Stop_Username_Enumeration();